#lang typed/racket
;;; Copyright 2011, Matthias Andreas Benkard.
;;;
;;;-----------------------------------------------------------------------------
;;; This program is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU Affero General Public License as published by
;;; the Free Software Foundation, either version 3 of the License, or
;;; (at your option) any later version.
;;;
;;; This program is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU Affero General Public License for more details.
;;;
;;; You should have received a copy of the GNU Affero General Public License
;;; along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;-----------------------------------------------------------------------------
;;;

(require "util.rkt")

(provide: [threefish (Bytes Bytes Bytes (U 'encrypt 'decrypt) -> Bytes)])

(define-type Long Exact-Nonnegative-Integer)

(: l+ (Long Long -> Long))
(define (l+ a b)
  (bitwise-and (+ a b) #xffffffffffffffff))

(: l- (Long Long -> Long))
(define (l- a b)
  (bitwise-and (- a b) #xffffffffffffffff))

(: lxor (Long Long -> Long))
(define lxor bitwise-xor)

(: lrot (Long Exact-Nonnegative-Integer -> Long))
(define (lrot a e)
  (let ([ash (arithmetic-shift a e)])
    (bitwise-ior (bitwise-and ash #xffffffffffffffff)
                 (arithmetic-shift ash -64))))

(: rrot (Long Exact-Nonnegative-Integer -> Long))
(define (rrot a e)
  (bitwise-ior (arithmetic-shift a (- 64 e))
               (arithmetic-shift a (- e))))

(define (threefish key tweak plaintext mode)
  (assert (= (bytes-length key) (bytes-length plaintext)))
  (assert (= (bytes-length tweak) 16))
  (let*: ([size   (bytes-length key)]
          [words  (quotient size 8)]
          [rounds (case size
                    [(32 64) 72]
                    [(128)   80]
                    [else    (error "Invalid key size")])]
          [pbox : (Vectorof Long)
           (case size
             [(32)  #(0 3 2 1)]
             [(64)  #(2 1 4 7 6 5 0 3)]
             [(128) #(0 9 2 13 6 11 4 15 10 7 12 3 14 5 8 1)]
             [else  (error "Invalid key size")])]
          [mixbox : (Vectorof (Vectorof Long))
           (case size
             [(32)  #(#( 5 56)
                      #(36 28)
                      #(13 46)
                      #(58 44)
                      #(26 20)
                      #(53 35)
                      #(11 42)
                      #(59 50))
                    #;
                    #(#(14 16)
                      #(52 57)
                      #(23 40)
                      #( 5 37)
                      #(25 33)
                      #(46 12)
                      #(58 22)
                      #(32 32))
                    #;
                    #(#(32 32)
                      #(58 22)
                      #(46 12)
                      #(25 33)
                      #( 5 37)
                      #(23 40)
                      #(52 57)
                      #(14 16))]
             [(64)  #(#(38 30 50 53)
                      #(48 20 43 31)
                      #(34 14 15 27)
                      #(26 12 58  7)
                      #(33 49  8 42)
                      #(39 27 41 14)
                      #(29 26 11  9)
                      #(33 51 39 35))]
             [(128) #(#(55 43 37 40 16 22 38 12)
                      #(25 25 46 13 14 13 52 57)
                      #(33  8 18 57 21 12 32 54)
                      #(34 43 25 60 44  9 59 34)
                      #(28  7 47 48 51  9 35 41)
                      #(17  6 18 25 43 42 40 15)
                      #(58  7 32 45 19 18  2 56)
                      #(47 49 27 58 37 48 53 56))]
             [else   (error "Invalid key size")])]
          [mix
           (lambda: ([d : Integer] [j : Integer] [x0 : Long] [x1 : Long])
             (let ([rotnum (vector-ref (vector-ref mixbox (if (eq? mode 'encrypt)
                                                              (modulo d 8)
                                                              (- 8 (modulo d 8))))
                                       j)])
               (if (eq? mode 'encrypt)
                 (let*: ([y0 : Long
                             (l+ x0 x1)]
                         [y1 : Long
                             (lxor (lrot x1 rotnum)
                                   y0)])
                   (values y0 y1))
                 (let*: ([y1 : Long
                             (rrot (lxor x0 x1)
                                   rotnum)]
                         [y0 : Long
                             (l- x0 y1)])
                   (values y0 y1)))))]
          [words->bytes
           : ((Vectorof Long) -> Bytes)
           (lambda (v)
             (bytes-append*
              (reverse
               (for/fold: ([blocks : (Listof Bytes) '()])
                          ([i : Exact-Nonnegative-Integer (in-range (vector-length v))])                 
                 (cons (integer->bytes/size (vector-ref v i) 'little-endian 8)
                       blocks)))))]
          [bytes->word-list
           : (Bytes -> (Listof Long))
           (lambda (b)
             (for/fold: ([words : (Listof Long) '()])
                        ([i : Exact-Nonnegative-Integer (in-range (quotient
                                                                   (bytes-length b)
                                                                   8))])
               (cons (bytes->integer/le (subbytes b (* i 8) (* (add1 i) 8)))
                     words)))]
          [bytes->words
           : (Bytes -> (Vectorof Long))
           (lambda (b)
             (list->vector (reverse (bytes->word-list b))))]
          [key-words : (Vectorof Long)
           (let ([ks (bytes->word-list key)])
             (list->vector
              (reverse
               (cons
                (foldl lxor (quotient (expt 2 64) 3) ks)
                ks))))]
          [tweak-words : (Vectorof Long)
           (let ([t0 (bytes->integer/le (subbytes tweak 0 8))]
                 [t1 (bytes->integer/le (subbytes tweak 8 16))])
             (vector t0 t1 (lxor t0 t1)))]
          [key-schedule
           : (Long Long -> Long)
           ;; XXX memoize?
           (lambda: ([s : Long] [i : Long])
             (let ([k (vector-ref key-words (modulo (l+ s i) (l+ words 1)))])
               (assert (< i words))
               (l+ k
                   (cond
                     [(= i (- words 1))
                      s]
                     [(= i (- words 2))
                      (vector-ref tweak-words (modulo (l+ s 1) 3))]
                     [(= i (- words 3))
                      (vector-ref tweak-words (modulo s        3))]
                     [else
                      0]))))]
          [make-subkey
           : (Long -> (Vectorof Long))
           (lambda: ([s : Long])
             (list->vector
              (reverse
               (for/fold: ([words : (Listof Long) '()])
                          ([i : Exact-Nonnegative-Integer (in-range words)])
                 (cons (key-schedule s i) words)))))]
          [state (bytes->words plaintext)])
    (printf "size: ~a, words: ~a, rounds: ~a~%" size words rounds)
    (for: ([round : Exact-Nonnegative-Integer (in-range rounds)])
      (printf "Round ~a: ~s~%" round (words->bytes state))
      ;;(printf ".")
      (let: ([e
              : (Vectorof Long)
              (if (zero? (modulo round 4))
                  (begin ;;(printf "PLUS!\n")
                    (vector-map l+
                              state
                              (make-subkey (quotient round 4)))
                    )
                  (vector-copy state))])
        (for: ([j : Exact-Nonnegative-Integer (in-range (quotient words 2))])
          ;;(printf "Mix.\n")
          (let-values ([(f0 f1)
                        (mix round
                             j
                             (vector-ref e (* 2 j))
                             (vector-ref e (add1 (* 2 j))))])
            (vector-set! e (* 2 j)        f0)
            (vector-set! e (add1 (* 2 j)) f1)))
        ;;(printf "~s~%" (words->bytes e))
        (for: ([i : Exact-Nonnegative-Integer (in-range words)])
          ;;(printf "Permute.\n")
          (vector-set! state i (vector-ref e (vector-ref pbox i))))))
    (vector-map! l+ state (make-subkey (quotient rounds 4)))
    ;;(vector-map! lxor state (bytes->words plaintext))
    (vector-map (lambda (x) (printf "~x " x)) state)
    (words->bytes state)))

;;; Test vector from the PySkein documentation.
(threefish #"key of 32,64 or 128 bytes length"
           ;;(integer->bytes/size #x00 'big-endian 32)
           ;;(integer->bytes/size #x00 'big-endian 8)
           ;;(integer->bytes/size #x00 'big-endian 32)
           #"tweak: 16 bytes "
           #"block of data,same length as key"
           'encrypt)
