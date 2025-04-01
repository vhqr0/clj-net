(ns clj-net.inet.pcap-test
  (:require [clojure.java.io :as io]
            [clj-bytes.core :as b]
            [clj-net.inet.core :as inet]
            [clj-net.inet.pcap :as pcap])
  (:import [java.io InputStream]))

(defn bytes-seq
  [^InputStream r]
  (let [b (b/make 4096)
        n (.read r b 0 4096)]
    (when (pos? n)
      (lazy-seq
       (cons (b/sub! b 0 n) (bytes-seq r))))))

(defn pcap-seq
  [r]
  (->> (bytes-seq r) (sequence (pcap/->pcap-read-xf))))

(defn packet-seq
  [r]
  (->> (pcap-seq r) rest (map :data)))

(defn parsed-packet-seq
  [r]
  (->> (packet-seq r) (map inet/parse-ether)))

(defn read-pcap
  [f]
  (parsed-packet-seq (io/input-stream f)))
