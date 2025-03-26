(ns clj-net.inet.tcp
  (:require [clj-bytes.struct :as st]
            [clj-net.inet.packet :as pkt]))

;; RFC 9293 TCP
;; RFC 7323 TCP extensions
;; RFC 2018 TCP sack

(def st-tcp
  (-> (st/key-fns
       :sport (constantly st/uint16-be)
       :dport (constantly st/uint16-be)
       :seq (constantly st/uint32-be)
       :ack (constantly st/uint32-be)
       :dtaofs-reserved (constantly (st/bits [4 4]))
       :cwr-ece-urg-ack-psh-rst-syn-fin (constantly (st/bits [1 1 1 1 1 1 1 1]))
       :window (constantly st/uint16-be)
       :chksum (constantly st/uint16-be)
       :urgptr (constantly st/uint16-be)
       :options #(st/bytes-fixed (* 4 (- (:dataofs %) 5))))
      (st/wrap-vec-destructs
       {:dataofs-reserved [:dataofs :reserved]
        :cwr-ece-urg-ack-psh-rst-syn-fin [:cwr :ece :urg :ack :psh :rst :syn :fin]})))

(def st-tcp-option
  (st/key-fns
   :type (constantly st/uint8)
   :data (fn [{:keys [type]}]
           (case type
             (0 1) (st/bytes-fixed 0)
             (-> st/uint8
                 (st/wrap #(+ % 2) #(- % 2))
                 st/bytes-var)))))

(def tcp-option-map
  (st/->kimap {:eol 0 :nop 1 :mss 2 :wscale 3 :sack-ok 4 :sack 5 :timestamp 6}))

(def tcp-option-mss
  st/uint16-be)

(def tcp-option-wscale
  st/uint8)

(def tcp-option-sack
  (st/coll-of st/uint32-be))

(def tcp-option-timestamp
  (st/keys
   :tsval st/uint32-be
   :tsecr st/uint16-be))

(defmethod pkt/parse :tcp [type opts context buffer]
  (pkt/parse-simple-packet
   st-tcp type opts context buffer
   (fn [{:keys [st] :as packet} context]
     (let [{:keys [sport dport]} st
           flags (->> #{:cwr :ece :urg :ack :psh :rst :syn :fin} (remove #(zero? (get st %))) set)
           context (merge context #:tcp{:sport sport :dport dport :flags flags})]
       [packet context]))))
