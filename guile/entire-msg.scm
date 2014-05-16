;;;
;;; entire-msg.scm
;;;
;;; This file is part of GNU Anubis.
;;; Copyright (C) 2003-2014 The Anubis Team.
;;;
;;; GNU Anubis is free software; you can redistribute it and/or modify it
;;; under the terms of the GNU General Public License as published by the
;;; Free Software Foundation; either version 3 of the License, or (at your
;;; option) any later version.
;;;
;;; GNU Anubis is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License along
;;; with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.

(use-modules (ice-9 popen)
             (ice-9 rdelim))

;; Starts program PROG with arguments ARGS
;; Returns a list:
;;   (PID OUTPUT-PORT INPUT-PORT)
;; Where
;;  PID          -- pid of the program
;;  OUTPUT-PORT  -- output port connected to the stdin of the program
;;  INPUT-PORT   -- input port connected to the stdout of the program
;; Note:
;;  When no longer needed, the returned list must be fed to
;;  (close-subprocess). See below.
(define (create-subprocess prog args)
  (let ((inp (pipe))
	(outp (pipe))
	(pid (primitive-fork)))
    (setvbuf (cdr inp) _IONBF)
    (setvbuf (cdr outp) _IONBF)
    ;; (car inp)  -> child current-input-port
    ;; (cdr inp)  -> parent write port
    ;; (car outp) -> parent read port
    ;; (cdr outp) -> child current-output-port
    (cond
     ((= pid 0)
      ;; Child
      (let ((in-fd (fileno (car inp)))
	    (out-fd (fileno (cdr outp)))
	    (err-fd (fileno (current-error-port))))
	(port-for-each (lambda (pt-entry)
			 (false-if-exception
			  (let ((pt-fileno (fileno pt-entry)))
			    (if (not (or (= pt-fileno in-fd)
					 (= pt-fileno out-fd)
					 (= pt-fileno err-fd)))
				(close-fdes pt-fileno))))))
	;; copy the three selected descriptors to the standard
	;; descriptors 0, 1, 2.  

	(cond ((not (= in-fd 0))
	       (if (= out-fd 0)
		   (set! out-fd (dup->fdes 0)))
	       (if (= err-fd 0)
		   (set! err-fd (dup->fdes 0)))
	       (dup2 in-fd 0)))

	(cond ((not (= out-fd 1))
	       (if (= err-fd 1)
		   (set! err-fd (dup->fdes 1)))
	       (dup2 out-fd 1)))
	
	(dup2 err-fd 2)
	
	(apply execlp prog prog args)))
     (else
      ;; Parent
      (close-port (car inp))
      (close-port (cdr outp))
      (list pid (cdr inp) (car outp))))))

;; Closes the communication channels and destroys the subprocess created
;; by (create-subprocess)
(define (close-subprocess p)
  (close-port (list-ref p 1))
  (close-port (list-ref p 2))
  (silent-waitpid (car p)))

;; Auxiliary function. Asynchronously feeds data to external program.
;; Returns pid of the feeder process.
(define (writer outport hdr body)
  (let ((pid (primitive-fork)))
    (cond
     ((= pid 0)
      (with-output-to-port
	  outport
	(lambda ()
	  (for-each
	   (lambda (x)
	     (display (car x))
	     (display ": ")
	     (display (cdr x))
	     (newline))
	   hdr)
	  (newline)
	  (display body)))
      (port-for-each close-port)
      (primitive-exit 0))
     (else
      ;; Parent
      (close-port outport)
      pid))))

;; Auxiliary function. Returns #t if LINE is an empty line.
(define (empty-line? line)
  (or (eof-object? line)
      (string-null? line)))

;; Read RFC822 headers from current input port and convert them
;; to the form understandable by Anubis
(define (read-headers port)
  (let ((hdr-list '())
	(header-name #f)
	(header-value ""))
    (do ((line (read-line port) (read-line port)))
	((empty-line? line) #t)
      (cond
       ((char-whitespace? (string-ref line 0))
	(set! header-value (string-append header-value line)))
       (else
	(if header-name
	    (set! hdr-list (append hdr-list
				   (list (cons header-name header-value)))))
	(let ((off (string-index line #\:)))
	  (set! header-name (substring line 0 off))
	  (set! header-value (substring
			      line
			      (do ((i (1+ off) (1+ i)))
				  ((not (char-whitespace?
					 (string-ref line i))) i))))))))
    (if header-name
	(set! hdr-list (append hdr-list
			       (list (cons header-name header-value)))))
    hdr-list))

;; Read message body from the current input port
(define (read-body port)
  (let ((text-list '()))
    (do ((line (read-line port) (read-line port)))
	((eof-object? line) #t)
      (set! text-list (append text-list (list line "\n"))))
    (apply string-append text-list)))

;; Auxiliary function. Reads output from the external program and
;; converts it to the internal Anubis representation.
(define (reader inport)
  (cons (read-headers inport) (read-body inport)))

(define (optarg-value opt-args tag)
  (cond
   ((member tag opt-args) =>
    (lambda (x)
      (car (cdr x))))
   (else
    #f)))

(define (silent-waitpid pid)
  (catch #t
	 (lambda ()
	   (waitpid pid))
	 (lambda args
	   #t)))

;; A Guile interface for feeding entire message (including headers)
;; to an external program.
;;
;; Usage:
;; BEGIN GUILE
;;   guile-load-program entire-msg.scm
;; END
;;
;; SECTION RULE
;;   guile-process entire-msg-filter PROGNAME [ARGS...]

(define (entire-msg-filter hdr body . rest)
  (let ((progname (car rest))
	(args (cdr rest)))
    (let* ((p (create-subprocess progname args))
	   (wrpid (writer (list-ref p 1) hdr body)))
      (let ((ret (reader (list-ref p 2))))
	(silent-waitpid wrpid)
	(close-subprocess p)
	ret))))

;; Openssl version 0.9.7d exhibits strange lossage: it attempts to
;; rewind the input stream even if it is a pipe. To overcome this,
;; we have to use a temporary file.
;;
;; Usage:
;; BEGIN GUILE
;;   guile-load-program entire-msg.scm
;; END
;;
;; BEGIN RULE
;;   guile-process openssl-filter /path/to/openssl smime -sign -signer FILE
;; END

(define (openssl-filter hdr body . rest)
  (let ((progname (car rest))
	(args (cdr rest))
	(tempfile "/tmp/ANXXXXXX"))

    (mkstemp! tempfile)
    (with-output-to-file
	tempfile
      (lambda ()
	(display body)))
    
    (let* ((p (create-subprocess progname
				 (append args (list "-in" tempfile)))))
      (let ((ret (reader (list-ref p 2))))
	(close-subprocess p)
	(delete-file tempfile)
	(cons (append hdr (car ret)) (cdr ret))))))

;; End of entire-msg.scm
