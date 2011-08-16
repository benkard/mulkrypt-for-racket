#lang racket
(require racket/stream)

(provide lazy-functional-stream-append)

(define (lazy-functional-stream-append seq thunk)
  (let-values ([(next? next) (sequence-generate seq)])
    (let loop ()
      (if (next?)
          (let ([x (next)])
            (stream-cons x (loop)))
          (thunk)))))
