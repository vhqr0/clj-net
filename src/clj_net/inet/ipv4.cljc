(ns clj-net.inet.ipv4
  (:require [clj-bytes.core :as b]
            [clj-bytes.struct :as st]
            [clj-net.inet.addr :as ia]
            [clj-net.inet.packet :as pkt]
            [clj-net.inet.ip :as ip]))

;; RFC 791

(def st-ipv4
  (-> (st/keys
       :version-ihl (st/bits [4 4])
       :tos st/uint8
       :len st/uint16-be
       :id st/uint16-be
       :res-df-mf-offset (st/bits [1 1 1 13])
       :ttl st/uint8
       :proto st/uint8
       :checksum st/uint16-be
       :src ia/st-ipv4
       :dst ia/st-ipv4
       :options (st/lazy #(st/bytes-fixed (* 4 (- (second (:version-ihl %)) 5)))))
      (st/wrap-vec-destructs
       {:version-ihl [:version :ihl]
        :res-df-mf-offset [:res :df :mf :offset]})
      (st/wrap-merge
       {:version 4 :ihl 5 :id 0 :res 0 :df 0 :mf 0 :offset 0 :ttl 64 :proto 0 :checksum 0
        :src ia/ipv4-zero :dst ia/ipv4-zero :options (b/empty)})))

(def ipv4-option-map
  (st/->kimap {:eol 0 :nop 1}))

(def st-ipv4-option
  (st/keys
   :type st/uint8
   :data (st/lazy
          (fn [{:keys [type]}]
            (case type
              (0 1) (st/bytes-fixed 0)
              (-> st/uint8
                  (st/wrap #(+ % 2) #(- % 2))
                  st/bytes-var))))))

(defmulti parse-ipv4-option
  (fn [option] (:type option)))

(defmethod parse-ipv4-option :default [option] option)
(defmethod parse-ipv4-option 0 [_option] {:type :eol})
(defmethod parse-ipv4-option 1 [_option] {:type :nop})

(defmethod pkt/parse :ipv4 [type _context buffer]
  (pkt/unpack-packet
   st-ipv4 type buffer
   (fn [{:keys [id proto offset src dst ihl len options]}]
     (let [options (->> (st/unpack-many options st-ipv4-option) (mapv parse-ipv4-option))]
       (merge (ip/parse-ip-result 4 id proto src dst (- len (* 4 ihl)) offset)
              {:data-extra {:options options}})))))
