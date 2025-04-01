(ns clj-net.inet.pcap-test
  (:require [clojure.java.io :as io]
            [clj-bytes.core :as b]
            [clj-net.inet.core :as inet]
            [clj-net.inet.pcap :as pcap])
  (:import [java.io InputStream]))

(defn read-seq
  [^InputStream r]
  (let [b (b/make 4096)
        n (.read r b 0 4096)]
    (when (pos? n)
      (lazy-seq
       (cons (b/sub! b 0 n) (read-seq r))))))

(defn pcap-seq
  [r]
  (->> (read-seq r) (sequence (pcap/->pcap-read-xf))))
