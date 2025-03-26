(ns clj-net.inet.ipv6
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]
            [clj-net.inet.ip :as ip]))

;; RFC 8200

(def st-ipv6
  (-> (st/keys
       :version-tc-fl (st/bits [4 8 20])
       :plen st/uint16-be
       :nh st/uint8
       :hlim st/uint8
       :src ia/st-ipv6
       :dst ia/st-ipv4)
      (st/wrap-vec-destructs
       {:version-tc-fl [:version :tc :fl]})))

(def st-ipv6-ext
  (st/keys
   :nh st/uint8
   :data (-> st/uint8
             (st/wrap-validator
              #(zero? (mod (- % 6) 8)))
             (st/wrap
              #(quot (- % 6) 8)
              #(+ 6 (* 8 %)))
             st/bytes-var)))

(def st-ipv6-ext-fragment
  (-> (st/keys
       :nh st/uint8
       :res1 st/uint8
       :offset-res2-m (st/bits [13 2 1])
       :id st/uint32-be)
      (st/wrap-vec-destructs
       {:offset-res2-m [:offset :res2 :m]})))

(def ipv6-option-map
  (st/->kimap {:pad1 0 :padn 1}))

(def st-ipv6-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             0 (st/bytes-fixed 0)
             (st/bytes-var st/uint8)))))

(def st-ipv6-options
  (st/coll-of st-ipv6-option))

(defn parse-ipv6-options
  [b {:ipv6/keys [option-map]}]
  (->> (st/unpack b st-ipv6-options)
       (map #(pkt/parse-option % option-map))
       reverse
       (drop-while (fn [[type _data]] (contains? #{:pad1 :padn} type)))
       reverse
       vec))

(defmethod pkt/parse :ipv6 [type opts context buffer]
  (pkt/parse-simple-packet
   st-ipv6 type opts context buffer
   (fn [packet context]
     (let [{:keys [nh src dst plen]} (:st packet)]
       (ip/parse-ip-xform opts packet context 6 nh src dst plen)))))

(defn parse-ipv6-ext-opts [type {:ipv6/keys [option-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-ipv6-ext type opts context buffer
   (fn [packet context]
     (let [{:keys [nh data]} (:st packet)
           options (parse-ipv6-options data option-map)
           packet (assoc packet :options options)]
       (ip/parse-ip-ext-xform packet context nh)))))

(defmethod pkt/parse :ipv6-ext-hbh-opts [type opts context buffer]
  (parse-ipv6-ext-opts type opts context buffer))

(defmethod pkt/parse :ipv6-ext-dest-opts [type opts context buffer]
  (parse-ipv6-ext-opts type opts context buffer))

(defmethod pkt/parse :ipv6-ext-fragment [_type opts context buffer]
  (pkt/parse-simple-packet
   st-ipv6-ext-fragment type opts context buffer
   (fn [packet context]
     (let [{:keys [nh]} (:st packet)]
       (ip/parse-ip-ext-xform packet context nh)))))
