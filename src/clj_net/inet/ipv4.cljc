(ns clj-net.inet.ipv4
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]))

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

(defmethod pkt/parse :ipv4 [type {:ip/keys [proto-map] :as opts} context buffer]
  (pkt/parse-simple-packet
   st-ipv4 type opts context buffer
   (fn [packet context]
     (let [{:keys [proto src dst ihl len]} (:st packet)
           plen (- len (* 5 ihl))
           next-type (get-in proto-map [:i->k proto])
           context (merge context #:ip{:version 4 :proto next-type :src src :dst dst :plen plen})]
       [packet context {:next-type next-type :next-length plen}]))))
