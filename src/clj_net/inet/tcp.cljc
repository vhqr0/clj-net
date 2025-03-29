(ns clj-net.inet.tcp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

;; RFC 9293 TCP
;; RFC 7323 TCP extensions
;; RFC 2018 TCP sack

(def st-tcp
  (-> (st/keys
       :sport st/uint16-be
       :dport st/uint16-be
       :seq st/uint32-be
       :ack st/uint32-be
       :dtaofs-res (st/bits [4 4])
       :cwr-ece-urg-ack-psh-rst-syn-fin (st/bits [1 1 1 1 1 1 1 1])
       :window st/uint16-be
       :chksum st/uint16-be
       :urgptr st/uint16-be
       :options (st/lazy #(st/bytes-fixed (* 4 (- (:dataofs %) 5)))))
      (st/wrap-vec-destructs
       {:dataofs-res [:dataofs :res]
        :cwr-ece-urg-ack-psh-rst-syn-fin [:cwr :ece :urg :ack :psh :rst :syn :fin]})))

(def st-tcp-option
  (st/keys
   :type st/uint8
   :data (st/lazy
          (fn [{:keys [type]}]
            (case type
              (0 1) (st/bytes-fixed 0)
              (-> st/uint8
                  (st/wrap #(+ % 2) #(- % 2))
                  st/bytes-var))))))

(def st-tcp-options
  (st/coll-of st-tcp-option))

(def tcp-option-map
  (st/->kimap {:eol 0 :nop 1 :mss 2 :wscale 3 :sack-ok 4 :sack 5 :timestamp 6}))

(def st-tcp-option-mss
  st/uint16-be)

(def st-tcp-option-wscale
  st/uint8)

(def st-tcp-option-sack
  (st/coll-of st/uint32-be))

(def st-tcp-option-timestamp
  (st/keys
   :tsval st/uint32-be
   :tsecr st/uint16-be))

(defmulti parse-tcp-option
  (fn [type _data] type))

(defmethod parse-tcp-option :default [_type _data])

(defmethod parse-tcp-option :mss [_type data]
  (-> data (st/unpack st-tcp-option-mss)))

(defmethod parse-tcp-option :wscale [_type data]
  (-> data (st/unpack st-tcp-option-wscale)))

(defmethod parse-tcp-option :sack [_type data]
  (-> data (st/unpack st-tcp-option-sack)))

(defmethod parse-tcp-option :timestamp [_type data]
  (-> data (st/unpack st-tcp-option-timestamp)))

(defn parse-tcp-options
  [b {:tcp/keys [option-map]}]
  (->> (st/unpack b st-tcp-options)
       (map #(pkt/parse-option % option-map parse-tcp-option))
       reverse
       (drop-while (fn [[type _data]] (= type :nop)))
       reverse
       vec))

(defmethod pkt/parse :tcp [type opts context buffer]
  (pkt/parse-simple-packet
   st-tcp type opts context buffer
   (fn [{:keys [st] :as packet} context]
     (let [{:keys [sport dport seq ack window options]} st
           flags (->> #{:cwr :ece :urg :ack :psh :rst :syn :fin} (remove #(zero? (get st %))) set)
           options (parse-tcp-options options opts)
           packet (assoc packet :flags flags :options options)
           context (merge context #:tcp{:sport sport :dport dport :seq seq :ack ack :window window :flags flags})]
       [packet context]))))
