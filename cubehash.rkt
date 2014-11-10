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

;;;
;;; NOTE:  The original version of CubeHash defaulted to
;;; init-rounds = fin-rounds = (* 10 rounds/block).  Therefore, if you see
;;; references to “Cubehash r/b-h” variants, you can instantiate those by using
;;; something like the following:
;;;
;;;  (cubehash (* 10 r) r b (* 10 r) h)
;;;


(require "util.rkt")

(provide: [cubehash      (Exact-Nonnegative-Integer Exact-Nonnegative-Integer
                          Exact-Nonnegative-Integer Exact-Nonnegative-Integer
                          Exact-Nonnegative-Integer ->
                          Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-128  (Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-160  (Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-224  (Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-256  (Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-384  (Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-512  (Bytes -> Exact-Nonnegative-Integer)]
          [cubehash-512x (Bytes -> Exact-Nonnegative-Integer)]
          #;[cubemac-128   (Bytes Bytes -> Exact-Nonnegative-Integer)])

(: cubehash      (Exact-Nonnegative-Integer Exact-Nonnegative-Integer
                  Exact-Nonnegative-Integer Exact-Nonnegative-Integer
                  Exact-Nonnegative-Integer ->
                  Bytes -> Exact-Nonnegative-Integer))
(: cubehash-128  (Bytes -> Exact-Nonnegative-Integer))
(: cubehash-160  (Bytes -> Exact-Nonnegative-Integer))
(: cubehash-224  (Bytes -> Exact-Nonnegative-Integer))
(: cubehash-256  (Bytes -> Exact-Nonnegative-Integer))
(: cubehash-384  (Bytes -> Exact-Nonnegative-Integer))
(: cubehash-512  (Bytes -> Exact-Nonnegative-Integer))
(: cubehash-512x (Bytes -> Exact-Nonnegative-Integer))
#;(: cubemac-128   (Bytes Bytes -> Exact-Nonnegative-Integer))


(define-type Word    Exact-Nonnegative-Integer)
(define-type Bit     (U Zero One))

(: w+ (Word Word -> Word))
(define (w+ a b)
  (bitwise-and (+ a b) #xffffffff))

(: wxor (Word Word -> Word))
(define wxor bitwise-xor)

(: wrot (Word Exact-Positive-Integer -> Word))
(define (wrot a e)
  (let ([ash (arithmetic-shift a e)])
    (bitwise-ior (bitwise-and ash #xffffffff)
                 (arithmetic-shift ash -32))))


(define (cubehash init-rounds rounds/block block-size fin-rounds output-bits)
  (λ: ([msg : Bytes])
    (let*: ([state   : (Vectorof Word)
                     (make-vector 32 #x0)]
            [msg-pad : Bytes
                     (bytes-append msg
                                   (list->bytes '(#x80))
                                   (make-bytes (modulo (- (+ 1 (bytes-length msg)))
                                                       block-size)
                                               #x0))]
            [x       : (Integer Integer Integer Integer Integer -> Word)
                     (λ (i j k l m)
                       (vector-ref state (+ (* i 16) (* j 8) (* k 4) (* l 2) m)))]
            [set-x!  : (Integer Integer Integer Integer Integer Word -> Void)
                     (λ (i j k l m v)
                       (vector-set! state (+ (* i 16) (* j 8) (* k 4) (* l 2) m) v))]
            [round!  : (-> Void)
                     (λ ()
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (set-x! 1 j k l m (w+ (x 0 j k l m)
                                               (x 1 j k l m))))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (set-x! 0 j k l m (wrot (x 0 j k l m) 7)))
                       (for*: ([k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (let ([tmp (x 0 0 k l m)])
                           (set-x! 0 0 k l m (x 0 1 k l m))
                           (set-x! 0 1 k l m tmp)))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (set-x! 0 j k l m (wxor (x 0 j k l m)
                                                 (x 1 j k l m))))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [m : Bit '(0 1)])
                         (let ([tmp (x 1 j k 0 m)])
                           (set-x! 1 j k 0 m (x 1 j k 1 m))
                           (set-x! 1 j k 1 m tmp)))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (set-x! 1 j k l m (w+ (x 0 j k l m)
                                               (x 1 j k l m))))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (set-x! 0 j k l m (wrot (x 0 j k l m) 11)))
                       (for*: ([j : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (let ([tmp (x 0 j 0 l m)])
                           (set-x! 0 j 0 l m (x 0 j 1 l m))
                           (set-x! 0 j 1 l m tmp)))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)] [m : Bit '(0 1)])
                         (set-x! 0 j k l m (wxor (x 0 j k l m)
                                                 (x 1 j k l m))))
                       (for*: ([j : Bit '(0 1)] [k : Bit '(0 1)] [l : Bit '(0 1)])
                         (let ([tmp (x 1 j k l 0)])
                           (set-x! 1 j k l 0 (x 1 j k l 1))
                           (set-x! 1 j k l 1 tmp))))])
      (vector-set! state 0 (quotient output-bits 8))
      (vector-set! state 1 block-size)
      (vector-set! state 2 rounds/block)
      (for ([i (in-range 0 init-rounds)])
        (round!))
      (for ([i (in-range 0 (quotient (bytes-length msg-pad) block-size))])
        (let ([block (subbytes msg-pad (* i block-size) (* (add1 i) block-size))])
          (for: ([byte : Byte block]
                 [i    : Exact-Nonnegative-Integer (in-naturals)])
            (let ([s (vector-ref state (quotient i 4))])
              (vector-set! state
                           (quotient i 4)
                           (bitwise-xor s (arithmetic-shift byte
                                                            (* (remainder i 4) 8))))))
          (for ([i (in-range 0 rounds/block)])
            (round!))))
      (vector-set! state 31 (bitwise-xor (vector-ref state 31) 1))
      (for ([i (in-range 0 fin-rounds)])
        (round!))
      (bytes->integer
       (subbytes (bytes-append* (vector->list
                                 (vector-map (λ: ([w : Word])
                                               (integer->bytes/size w 'little-endian 4))
                                             state)))
                 0
                 (quotient output-bits 8))))))


(define cubehash-128  (cubehash 16 16 32 32 128))
(define cubehash-160  (cubehash 16 16 32 32 160))
(define cubehash-224  (cubehash 16 16 32 32 224))
(define cubehash-256  (cubehash 16 16 32 32 256))
(define cubehash-384  (cubehash 16 16 32 32 384))
(define cubehash-512  (cubehash 16 16 32 32 512))
(define cubehash-512x (cubehash 16 16 1  32 512))

#;(define cubemac-128 ...)
