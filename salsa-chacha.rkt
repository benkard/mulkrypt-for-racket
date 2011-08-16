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

(provide salsa20)

(require/typed racket
               [sequence-generate (All (a)
                                    (Sequenceof a)
                                    -> (values (-> Boolean)
                                               (-> a)))]
               #;[in-producer (All (a)
                              ((-> Any)
                               Any
                               -> (Sequenceof a)))]
               [in-producer ((-> (U Byte Symbol))
                             Symbol
                             -> (Sequenceof Byte))])

(require/typed "typed-stream.rkt"
               [lazy-functional-stream-append (All (a)
                                               ((Sequenceof a)
                                                (-> (Sequenceof a))
                                                -> (Sequenceof a)))])

(define-type Word    Exact-Nonnegative-Integer)
(define-type 4words  (Vector Word Word Word Word))
(define-type 16words (Vector Word Word Word Word
                             Word Word Word Word
                             Word Word Word Word
                             Word Word Word Word))

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


(: quarterround (4words -> 4words))
(define (quarterround y)
  (match y
    [(vector y0 y1 y2 y3)
     (let* ([z1 (wxor y1 (wrot (w+ y0 y3) 7))]
            [z2 (wxor y2 (wrot (w+ z1 y0) 9))]
            [z3 (wxor y3 (wrot (w+ z2 z1) 13))]
            [z0 (wxor y0 (wrot (w+ z3 z2) 18))])
       (vector z0 z1 z2 z3))]))

(: chacha-quarterround (4words -> 4words))
(define (chacha-quarterround y)
  (match y
    [(vector a b c d)
     (let* ([a2 (w+ a  b)]  [d2 (wrot (wxor a2 d)  16)]
            [c2 (w+ c  d2)] [b2 (wrot (wxor b  c2)  12)]
            [a3 (w+ a2 b2)] [d3 (wrot (wxor d2 a3) 8)]
            [c3 (w+ c2 d3)] [b3 (wrot (wxor b2 c2) 7)])
       (vector a3 b3 c3 d3))]))

(: rowround (16words -> 16words))
(define (rowround y)
  (match y
    [(vector y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15)
     (match (vector (quarterround (vector y0 y1 y2 y3))
                    (quarterround (vector y5 y6 y7 y4))
                    (quarterround (vector y10 y11 y8 y9))
                    (quarterround (vector y15 y12 y13 y14)))
       [(vector (vector z0  z1  z2 z3) (vector z5  z6  z7  z4)
                (vector z10 z11 z8 z9) (vector z15 z12 z13 z14))
        (vector z0 z1 z2 z3 z4 z5 z6 z7 z8 z9 z10 z11 z12 z13 z14 z15)])]))

(: columnround (16words -> 16words))
(define (columnround y)
  (match y
    [(vector y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15)
     (match (vector (quarterround (vector y0 y4 y8 y12))
                    (quarterround (vector y5 y9 y13 y1))
                    (quarterround (vector y10 y14 y2 y6))
                    (quarterround (vector y15 y3 y7 y11)))
       [(vector (vector z0  z4  z8 z12) (vector z5  z9 z13 z1)
                (vector z10 z14 z2 z6)  (vector z15 z3 z7  z11))
        (vector z0 z1 z2 z3 z4 z5 z6 z7 z8 z9 z10 z11 z12 z13 z14 z15)])]))

(: doubleround (16words -> 16words))
(define doubleround (compose rowround columnround))

#;
(: 16words? (Any -> Boolean : 16words))
#;
(define (16words? x)
  (match x
    [(vector y0 y1 y2 y3 y4 y5 y6 y7 y8 y9 y10 y11 y12 y13 y14 y15)
     #t]
    [_
     #f]))

(: little-endian (Bytes -> Word))
(define (little-endian b)
  (match (bytes->list b)
    [(list b0 b1 b2 b3)
     (+ (arithmetic-shift b3 24)
        (arithmetic-shift b2 16)
        (arithmetic-shift b1 8)
        b0)]))

(: anti-little-endian (Word -> Bytes))
(define (anti-little-endian w)
  (integer->bytes/size w 'little-endian 4))

(: times (All (a) ((a -> a) Integer -> (a -> a))))
(define (times fn n)
  (for/fold ([acc (inst identity a)])
            ([i   (in-range 0 n)])
    (compose fn acc)))

(: salsa20h (Bytes -> Bytes))
(define (salsa20h x)
  (let*: ([xwords : 16words (vector 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0)])
    (for ([i (in-range 0 16)])
      (vector-set! (ann xwords (Vectorof Word))
                   i
                   (little-endian (subbytes x (* i 4) (* (add1 i) 4)))))
    (let ([zwords ((times doubleround 10) xwords)])
      (bytes-append* (vector->list
                      (vector-map (λ: ([a : Word] [b : Word])
                                    (anti-little-endian (w+ a b)))
                                  (ann xwords (Vectorof Word))
                                  (ann zwords (Vectorof Word))))))))

(: salsa20k (Bytes Bytes -> Bytes))
(define (salsa20k k n)
  (let* ([s0 (list->bytes '(101 120 112  97))]
         [s1 (list->bytes '(110 100  32  51))]
         [s2 (list->bytes '( 50  45  98 121))]
         [s3 (list->bytes '(116 101  32 107))]
         [t0 s0]
         [t1 (list->bytes '(110 100  32  49))]
         [t2 s2]
         [t3 s3])
    (if (= (bytes-length k) 32)
        (let ([k0 (subbytes k 0 16)]
              [k1 (subbytes k 16)])
          (salsa20h (bytes-append s0 k0 s1 n s2 k1 s3)))
        (salsa20h (bytes-append t0 k t1 n t2 k t3)))))

(: salsa20 (Bytes Bytes (Sequenceof Byte) -> (Sequenceof Byte)))
(define (salsa20 k v m)
  (let-values ([(next? next) (sequence-generate m)])
    (let: ([i      : Word          0]
           [buffer : (Listof Byte) (list)])
       (in-producer
        (λ ()
          (when (null? buffer)
            (let ([64bytes
                   (let: inner-loop : Bytes
                         ([k     : Integer       0]
                          [bytes : (Listof Byte) (list)])
                     (if (and (next?) (< k 64))
                         (inner-loop (add1 k) (cons (next) bytes))
                         (list->bytes bytes)))]
                  [i-code
                   (integer->bytes/size i 'little-endian 8)])
              (set! buffer (bytes->list (bytes-xor 64bytes
                                                   (salsa20k k (bytes-append v i-code)))))))
          (if (null? buffer)
              'end-of-sequence
              (let ([byte (first buffer)])
                (set! buffer (rest buffer))
                byte)))
        'end-of-sequence))))
