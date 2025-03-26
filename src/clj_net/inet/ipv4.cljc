(ns clj-net.inet.ipv4
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]
            [clj-net.inet.ip :as ip]))

;; RFC 791

(def st-ipv4
  (-> (st/key-fns
       :version-ihl (constantly (st/bits [4 4]))
       :tos (constantly st/uint8)
       :len (constantly st/uint16-be)
       :id (constantly st/uint16-be)
       :res-df-mf-frag (constantly (st/bits [1 1 1 13]))
       :ttl (constantly st/uint8)
       :proto (constantly st/uint8)
       :chksum (constantly st/uint8)
       :src (constantly ia/st-ipv4)
       :dst (constantly ia/st-ipv4)
       :options #(st/bytes-fixed (* 4 (- (:ihl %) 5))))
      (st/wrap-vec-destructs
       {:version-ihl [:version :ihl]
        :res-df-mf-frag [:res :df :mf :frag]})))

(def ipv4-option-map
  (st/->kimap {:eol 0 :nop 1}))

(def st-ipv4-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             (0 1) (st/bytes-fixed 0)
             (-> st/uint8
                 (st/wrap #(+ % 2) #(- % 2))
                 st/bytes-var)))))

(def st-ipv4-options
  (st/coll-of st-ipv4-option))

(defn parse-ipv4-options
  [b {:ipv4/keys [option-map]}]
  (->> (st/unpack b st-ipv4-options)
       (map #(pkt/parse-option % option-map))
       reverse
       (drop-while (fn [[type _data]] (= type :nop)))
       reverse
       vec))

(defmethod pkt/parse :ipv4 [type opts context buffer]
  (pkt/parse-simple-packet
   st-ipv4 type opts context buffer
   (fn [packet context]
     (let [{:keys [proto src dst ihl len options]} (:st packet)
           packet (cond-> packet
                    (not (b/empty? options))
                    (assoc :options (parse-ipv4-options options opts)))]
       (ip/parse-ip-xform opts packet context 4 proto src dst (- len (* 5 ihl)))))))
