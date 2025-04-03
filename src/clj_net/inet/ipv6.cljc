(ns clj-net.inet.ipv6
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]
            [clj-net.inet.ip :as ip]))

;; RFC 8200 IPv6
;; RFC 4303 IPv6 ESP

(def st-ipv6
  (-> (st/keys
       :version-tc-fl (st/bits [4 8 20])
       :plen st/uint16-be
       :nh st/uint8
       :hlim st/uint8
       :src ia/st-ipv6
       :dst ia/st-ipv6)
      (st/wrap-vec-destructs
       {:version-tc-fl [:version :tc :fl]})
      (st/wrap-merge
       {:version 6 :tc 0 :fl 0 :nh 59 :hlim 64
        :src ia/ipv6-zero :dst ia/ipv6-zero})))

(def st-ipv6-ext
  (-> (st/keys
       :nh st/uint8
       :data (-> st/uint8
                 (st/wrap
                  #(quot (- % 6) 8)
                  #(+ (* 8 %) 6))
                 (st/wrap-validator
                  #(and (nat-int? %) (zero? (mod (- % 6) 8))))
                 st/bytes-var))
      (st/wrap-merge
       {:nh 59})))

(def st-ipv6-ext-fragment
  (-> (st/keys
       :nh st/uint8
       :res1 st/uint8
       :offset-res2-m (st/bits [13 2 1])
       :id st/uint32-be)
      (st/wrap-vec-destructs
       {:offset-res2-m [:offset :res2 :m]})
      (st/wrap-merge
       {:nh 59 :res1 0 :offset 0 :res2 0 :m 0 :id 0})))

(def ipv6-option-map
  (st/->kimap {:pad1 0 :padn 1}))

(def st-ipv6-option
  (st/keys
   :type st/uint8
   :data (st/lazy
          (fn [{:keys [type]}]
            (case type
              0 (st/bytes-fixed 0)
              (st/bytes-var st/uint8))))))

(defmulti parse-ipv6-option
  (fn [option] (:type option)))

(defmethod parse-ipv6-option :default [option] option)
(defmethod parse-ipv6-option 0 [_option] {:type :pad1})
(defmethod parse-ipv6-option 1 [option] (assoc option :type :padn))

(defn parse-ipv6-options
  [b]
  (->> (st/unpack-many b st-ipv6-option)
       (mapv parse-ipv6-option)))

(defmethod pkt/parse :ipv6 [type _context buffer]
  (pkt/unpack-packet
   st-ipv6 type buffer
   (fn [{:keys [nh fl src dst plen]}]
     (ip/parse-ip-result 6 fl nh src dst plen 0))))

(defn parse-ipv6-ext-opts [type buffer]
  (pkt/unpack-packet
   st-ipv6-ext type buffer
   (fn [{:keys [nh data]}]
     (merge (ip/parse-ip-ext-result nh)
            {:data-extra {:options (parse-ipv6-options data)}}))))

(defmethod pkt/parse :ipv6-ext-hbh-opts [type _context buffer]
  (parse-ipv6-ext-opts type buffer))

(defmethod pkt/parse :ipv6-ext-dest-opts [type _context buffer]
  (parse-ipv6-ext-opts type buffer))

(defmethod pkt/parse :ipv6-ext-routing [type _context buffer]
  (pkt/unpack-packet st-ipv6-ext type buffer #(ip/parse-ip-ext-result (:nh %))))

(defmethod pkt/parse :ipv6-ext-esp [type _context buffer]
  (pkt/unpack-packet st-ipv6-ext type buffer #(ip/parse-ip-ext-result (:nh %))))

(defmethod pkt/parse :ipv6-ext-ah [type _context buffer]
  (pkt/unpack-packet st-ipv6-ext type buffer #(ip/parse-ip-ext-result (:nh %))))

(defmethod pkt/parse :ipv6-ext-fragment [type _context buffer]
  (pkt/unpack-packet
   st-ipv6-ext-fragment type buffer
   (fn [{:keys [nh offset]}]
     (ip/parse-ip-ext-result nh offset))))
