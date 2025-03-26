(ns clj-net.inet.ipv6
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

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

(defmethod pkt/parse :ipv6 [type {:ip/keys [proto-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-ipv6 type opts context buffer
   (fn [packet context]
     (let [{:keys [nh src dst plen]} (:st packet)
           next-type (get-in proto-map [:i->k nh])]
       [packet
        (merge context #:ip{:version 6 :proto next-type :src src :dst dst :plen plen})
        {:next-type next-type :next-length plen}]))))

(defn parse-ipv6-ext [type {:ip/keys [proto-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-ipv6-ext type opts context buffer
   (fn [packet context]
     (let [{:keys [nh]} (:st packet)
           next-type (get-in proto-map [:i->k nh])
           context (merge context #:ip{:proto next-type})]
       [packet context {:next-type next-type}]))))

(defmethod pkt/parse :ipv6-ext-hbh-opts [type opts context buffer]
  (parse-ipv6-ext type opts context buffer))

(defmethod pkt/parse :ipv6-ext-dest-opts [type opts context buffer]
  (parse-ipv6-ext type opts context buffer))

(defmethod pkt/parse :ipv6-ext-fragment [_type {:ip/keys [proto-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-ipv6-ext-fragment type opts context buffer
   (fn [packet context]
     (let [{:keys [nh offset]} (:st packet)
           next-type (when (zero? offset) (get-in proto-map [:i->k nh]))
           context (merge context #:ip{:proto next-type})]
       [packet context {:next-type next-type}]))))
