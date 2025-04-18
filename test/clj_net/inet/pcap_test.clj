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
  (->> (pcap-seq r)
       rest
       (map
        (fn [{:keys [data] :as packet-info}]
          (let [[layers context] (inet/parse-ether data)]
            {:layers layers :context context :packet-info packet-info})))))

(defn read-pcap
  [f]
  (packet-seq (io/input-stream f)))
