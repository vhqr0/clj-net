(ns clj-net.inet.pcap
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]))

(def pcap-be-ms-magic 0xa1b2c3d4)
(def pcap-le-ms-magic 0xd4c3b2a1)
(def pcap-be-ns-magic 0xa1b23c4d)
(def pcap-le-ns-magic 0x4d3cb2a1)

(def pcap-magic-map
  (st/->kimap
   {:be-ms pcap-be-ms-magic
    :le-ms pcap-le-ms-magic
    :be-ns pcap-be-ns-magic
    :le-ns pcap-le-ns-magic}))

(def st-pcap-magic
  (st/enum st/uint32-be pcap-magic-map))

(defn st-pcap-header
  [be?]
  (let [st-uint16 (if be? st/uint16-be st/uint16-le)
        st-uint32 (if be? st/uint32-be st/uint32-le)]
    (st/keys
     :vermaj st-uint16
     :vermin st-uint16
     :tz st-uint32
     :sig st-uint32
     :snaplen st-uint32
     :linktype st-uint32)))

(defn st-pcap-packet
  [be?]
  (let [st-uint32 (if be? st/uint32-be st/uint32-le)]
    (st/keys
     :sec st-uint32
     :usec st-uint32
     :caplen st-uint32
     :wirelen st-uint32
     :data (st/lazy #(st/bytes-fixed (:caplen %))))))

(defn ->pcap-read-state
  []
  {:stage :wait-magic :buffer (b/empty)})

(defmulti advance-pcap-read-state
  (fn [state] (:stage state)))

(defmethod advance-pcap-read-state :wait-magic [state]
  (let [{:keys [buffer]} state]
    (if-let [[magic buffer] (-> buffer (st/unpack st-pcap-magic))]
      (let [be? (contains? #{:be-ms :be-ns} magic)
            st-header (st-pcap-header be?)
            st-packet (st-pcap-packet be?)]
        (-> state
            (assoc :stage :wait-header :buffer buffer :magic magic
                   :be? be? :st-header st-header :st-packet st-packet)
            advance-pcap-read-state))
      [nil state])))

(defmethod advance-pcap-read-state :wait-header [state]
  (let [{:keys [st-header buffer]} state]
    (if-let [[header buffer] (-> buffer (st/unpack st-header))]
      (let [[s state] (-> state
                          (assoc :stage :wait-packet :buffer buffer :header header)
                          advance-pcap-read-state)]
        [(cons header s) state])
      [nil state])))

(defmethod advance-pcap-read-state :wait-packet [state]
  (let [{:keys [st-packet buffer]} state]
    (if-let [[packet buffer] (-> buffer (st/unpack st-packet))]
      (let [[s state] (-> state
                          (assoc :buffer buffer)
                          (advance-pcap-read-state))]
        [(cons packet s) state])
      [nil state])))

(defn ->pcap-read-xf
  []
  (let [vstate (volatile! (->pcap-read-state))]
    (fn [rf]
      (fn
        ([] (rf))
        ([result]
         (let [{:keys [stage buffer]} @vstate]
           (assert (and (= stage :wait-packet) (b/empty? buffer)))
           (rf result)))
        ([result input]
         (vswap! vstate update :buffer b/concat! input)
         (let [[s state] (advance-pcap-read-state @vstate)]
           (vreset! vstate state)
           (->> s (reduce rf result))))))))

(defn ->pcap-write-xf
  [opts]
  (let [{:keys [magic vermaj vermin tz sig snaplen linktype]
         :or {magic :be-ms vermaj 2 vermin 4 tz 0 sig 0 snaplen 4096 linktype 1}}
        opts
        be? (contains? #{:be-ms :be-ns} magic)
        st-header (st-pcap-header be?)
        st-packet (st-pcap-packet be?)
        header (b/concat!
                (-> magic (st/pack st-pcap-magic))
                (-> {:vermaj vermaj :vermin vermin :tz tz :sig sig :snaplen snaplen :linktype linktype} (st/pack st-header)))
        vinit? (volatile! false)]
    (fn [rf]
      (fn
        ([] (rf))
        ([result]
         (if @vinit?
           (rf result)
           (do
             (vreset! vinit? true)
             (-> result (rf header) unreduced rf))))
        ([result input]
         (let [packet (-> input (st/pack st-packet))]
           (if @vinit?
             (rf result packet)
             (do
               (vreset! vinit? true)
               (->> [header packet] (reduce rf result))))))))))
