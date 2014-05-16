;;; anubis-mode.el --- major mode for editing GNU Anubis configuration files

;; Authors: 2003 Sergey Poznyakoff
;; Version:  1.0
;; Keywords: anubis
;; $Id$

;; This file is part of GNU Anubis.
;; Copyright (C) 2003-2014 The Anubis Team.

;; GNU Anubis is free software; you can redistribute it and/or modify it
;; under the terms of the GNU General Public License as published by the
;; Free Software Foundation; either version 3, or (at your option) any
;; later version.

;; GNU Anubis is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License along
;; with GNU Anubis.  If not, see <http://www.gnu.org/licenses/>.

;; Installation.
;;  Usually the normal installation is performed by make install.
;;  However, if you wish or have to install this module manually,
;;  please notice the following:
;;
;;  You may wish to use precompiled version of the module. To create it
;;  run:
;;    emacs -batch -f batch-byte-compile anubis-mode.el
;;  Install files anubis-mode.el and anubis-mode.elc to any directory in
;;  Emacs's load-path.

;; Customization:
;;  To your .emacs or site-start add:
;;  (autoload 'anubis-mode "anubis-mode")
;;  (setq auto-mode-alist (append auto-mode-alist
;;                                '(("/.anubisrc$" . anubis-mode)
;;                                  ("/anubisrc$" . anubis-mode))))

;; You may also wish to modify the following variables:
;;  anubis-section-body-indent -- Indent level for a section body. Defaults
;;                                to 0.
;;  anubis-level-indent        -- Amount of indentation per block nesting
;;                                level. Defaults to 2.

(eval-when-compile
  ;; We use functions from these modules
  (mapcar 'require '(info compile font-lock)))

(defvar anubis-mode-syntax-table nil
  "Syntax table used in anubis-mode buffers.")

(unless anubis-mode-syntax-table
  (setq anubis-mode-syntax-table (make-syntax-table))
  (modify-syntax-entry ?\# "<" anubis-mode-syntax-table)
  (modify-syntax-entry ?\n ">" anubis-mode-syntax-table)
  (modify-syntax-entry ?\t "-" anubis-mode-syntax-table)
  (modify-syntax-entry ?- "w" anubis-mode-syntax-table)
  (modify-syntax-entry ?_ "w" anubis-mode-syntax-table))

(defvar anubis-mode-abbrev-table nil
  "Abbrev table in use in anubis-mode buffers.")

(define-abbrev-table 'anubis-mode-abbrev-table
  '(("BE" "BEGIN " nil 0)
    ("EN" "END" nil 0)
    ("ru" "rule " nil 0)
    ("tri" "trigger " nil 0)
    ("hea" "header " nil 0)))

(defvar anubis-mode-map ()
  "Keymap used in anubis-mode buffers.")

(unless anubis-mode-map
  (setq anubis-mode-map (make-sparse-keymap))

  (define-key anubis-mode-map "\t" 'anubis-complete-or-indent)
  (define-key anubis-mode-map "\e\t" 'anubis-indent-line)
  (define-key anubis-mode-map "\e?" 'anubis-describe-keywords)
  (define-key anubis-mode-map "\C-c\C-c" 'anubis-check-syntax)

  (define-key anubis-mode-map [menu-bar] (make-sparse-keymap))
  (define-key anubis-mode-map [menu-bar Anubis]
    (cons "Anubis" anubis-mode-map))
  (define-key anubis-mode-map [anubis-check-syntax]
    '("Check syntax" . anubis-check-syntax)))

(defvar anubis-path nil
  "Path to the anubis executable")

(defvar anubis-section-body-indent 0
  "Indent of a section body in an Anubis rc file")
(defvar anubis-level-indent 2
  "Amount of additional indentation per nesting level of statements")


;; Font lock stuff

(defconst anubis-font-lock-keywords
  (eval-when-compile
    (list
     (list "\\(BEGIN\\)[ \t]+\\(\\sw+\\)"
	   '(1 font-lock-keyword-face)
	   '(2 font-lock-function-name-face))
     (cons "^\\s *\\(---\\)?\\s *END\\s *\\(---\\)?" font-lock-keyword-face)
     (cons (regexp-opt
	    '("if" "else" "fi" "rule" "trigger" "done")
	    'words)
	   font-lock-keyword-face)
     (cons (regexp-opt
	    '("stop" "call" "add" "remove" "modify" "regexp") 'words)
	   font-lock-keyword-face)
     (cons (regexp-opt
	    '("and" "or" "not") 'words)
	   font-lock-keyword-face)
     (cons (regexp-opt
	     '("header" "body" "command") 'words)
	   font-lock-type-face)
     (cons (regexp-opt
	    '("bind"
	      "rule-priority"
	      "control-priority"
              "termlevel"
              "allow-local-mta"
              "user-notprivileged"
              "drop-unknown-user"
              "loglevel"
              "logfile"
	      "tracefile"
              "remote-mta"
              "local-mta"
	      "esmtp-allowed-mech"
	      "esmtp-require-encryption"
	      "esmtp-auth-id"
	      "esmtp-authz-id"
	      "esmtp-password"
              "esmtp-auth"
	      "esmtp-service"
	      "esmtp-hostname"
	      "esmtp-generic-service"
	      "esmtp-passcode"
	      "esmtp-realm"
	      "esmtp-anonymous-token"
	      "mode"
	      "smtp-greeting-message"
	      "smtp-help-message"
	      "sasl-password-db"
	      "sasl-allowed-mech"
              "socks-proxy"
              "socks-v4"
              "socks-auth"
              "read-entire-body"
              "ssl"
              "ssl-oneway"
              "ssl-cert"
              "ssl-key"
              "ssl-cafile"
              "signature-file-append"
              "body-append"
              "body-clear-append"
              "body-clear"
              "external-body-processor"
              "gpg-passphrase"
              "gpg-encrypt"
              "gpg-sign"
	      "gpg-sign-encrypt"
	      "gpg-se"
              "gpg-home"
              "guile-output"
              "guile-debug"
              "guile-load-path-append"
              "guile-load-program"
	      "guile-debug"           
	      "guile-load-path-append"
	      "guile-load-program" 
	      "guile-rewrite-line"    
	      "guile-process") 'words)
	   font-lock-keyword-face)

     (list (concat ":"
		   (regexp-opt
		    '("re" "regex"
		      "perl" "perlre"
		      "ex" "exact"
		      "scase"
		      "icase"
		      "basic"
		      "extended") t)) ; FIXME: 'words does not work
	   1 font-lock-builtin-face)
     
     (list "#:\\(\\sw+\\)" 1 font-lock-constant-face 'prepend)

     (cons "\\[\\sw+\\]" font-lock-string-face) ) )
     
  "Expressions to highlight in Anubis mode.")




;; A list of keywords allowed in each section

(defconst anubis-keyword-dict
  ;; section     Keyword-list
  '((nil         BEGIN)
		 
    (CONTROL     END
                 bind                
                 (termlevel      normal
				 verbose
				 debug
				 silent)
                 (allow-local-mta     yes no)
                 user-notprivileged  
                 (loglevel       none
				 fails
				 all)
                 logfile
		 tracefile
                 remote-mta
                 local-mta
		 esmtp-allowed-mech
		 esmtp-require-encryption
		 esmtp-auth-id
		 esmtp-authz-id
		 esmtp-password
		 esmtp-auth
		 esmtp-service
		 esmtp-hostname
		 esmtp-generic-service
		 esmtp-passcode
		 esmtp-realm
		 esmtp-anonymous-token
		 (mode           transparent
				 auth)
                 socks-proxy         
                 (socks-v4       yes no)
                 socks-auth         
                 read-entire-body   
                 (drop-unknown-user  yes no)
                 (rule-priority      system
				     user
				     system-only
				     user-only)
                 (control-priority   yes no)
		 (ssl            yes no)
		 (ssl-oneway     yes no)
		 (ssl-cert       yes no)
		 (ssl-key        yes no)
		 (ssl-cafile     yes no))

    (AUTH        END
		 smtp-greeting-message
		 smtp-help-message
		 sasl-password-db
		 sasl-allowed-mech)

    (TRANSLATION END
                 translate)
    
    (GUILE       END
                 guile-output
		 (guile-debug    yes no)
		 guile-load-path-append
		 guile-load-program)
    
    (RULE        END
                 if 
		 else
		 fi
		 trigger
		 done
		 add
		 remove
		 modify
		 call
		 stop
		 regex
		 (signature-file-append yes no)
		 body-append
		 (body-clear yes no)
		 body-clear-append
		 gpg-passphrase
		 gpg-encrypt
		 gpg-sign
		 gpg-sign-encrypt
		 gpg-se
		 external-body-processor
		 guile-process)))

(defconst anubis-keyword-nodes
  ;; Block kwd                   Info node            Opt. Info file     
  '(("CONTROL"                  "CONTROL Section")
    ("AUTH"                     "AUTH Section")
    ("TRANSLATION"              "TRANSLATION Section")
    ("translate"                "TRANSLATION Section")
    ("GUILE"                    "GUILE Section")
    ("RULE"                     "Rule System")

    ("bind"                     "Basic Settings")
    ("remote-mta"               "Basic Settings")
    ("local-mta"                "Basic Settings")
    ("mode"                     "Basic Settings")

    ("smtp-greeting-message"    "AUTH Section")
    ("smtp-help-message"        "AUTH Section")
    ("sasl-password-db"         "AUTH Section")
    ("sasl-allowed-mech"        "AUTH Section")

    ("termlevel"                "Output Settings")
    ("logfile"                  "Output Settings")
    ("loglevel"                 "Output Settings")
    ("tracefile"                "Output Settings")

    ("socks-proxy"              "Proxy Settings")
    ("socks-v4"                 "Proxy Settings")
    ("socks-auth"               "Proxy Settings")

    ("esmtp-allowed-mech"       "ESMTP Authentication Settings")
    ("esmtp-require-encryption" "ESMTP Authentication Settings")
    ("esmtp-auth-id"            "ESMTP Authentication Settings")
    ("esmtp-authz-id"           "ESMTP Authentication Settings")
    ("esmtp-password"           "ESMTP Authentication Settings")
    ("esmtp-auth"               "ESMTP Authentication Settings")
    ("esmtp-service"            "ESMTP Authentication Settings")
    ("esmtp-hostname"           "ESMTP Authentication Settings")
    ("esmtp-generic-service"    "ESMTP Authentication Settings")
    ("esmtp-passcode"           "ESMTP Authentication Settings")
    ("esmtp-realm"              "ESMTP Authentication Settings")
    ("esmtp-anonymous-token"    "ESMTP Authentication Settings")

    ("ssl"                      "Encryption Settings")
    ("ssl-oneway"               "Encryption Settings")
    ("ssl-cert"                 "Encryption Settings")
    ("ssl-key"                  "Encryption Settings")
    ("ssl-cafile"               "Encryption Settings")

    ("allow-local-mta"          "Security Settings")
    ("drop-unknown-user"        "Security Settings")
    ("user-notprivileged"       "Security Settings")
    ("rule-priority"            "Security Settings")
    ("control-priority"         "Security Settings")

    ("stop"                     "Stop Action")
    ("call"                     "Call Action")
    ("add"                      "Adding Headers or Text")
    ("remove"                   "Removing Headers")
    ("modify"                   "Modifying Messages")
    ("signature-file-append"    "Inserting Files")
    ("body-append"              "Inserting Files")
    ("body-clear"               "Inserting Files")
    ("body-clear-append"        "Inserting Files")
    ("gpg-passphrase"           "Mail Encryption")
    ("gpg-encrypt"              "Mail Encryption")
    ("gpg-sign"                 "Mail Encryption")
    ("gpg-sign-encrypt"         "Mail Encryption")
    ("gpg-se"                   "Mail Encryption")
    ("external-body-processor"  "External Processor")
    ("guile-process"            "Invoking Guile Actions")
    ("guile-output"             "GUILE Section") 
    ("guile-debug"              "GUILE Section")
    ("guile-load-path-append"   "GUILE Section")
    ("guile-load-program"       "GUILE Section")

    ("if"                       "Conditional Statements")
    ("fi"                       "Conditional Statements")
    ("else"                     "Conditional Statements")
    ("trigger"                  "Triggers")
    ("rule"                     "Triggers")

    (":regex"                   "Regular Expressions")
    (":re"                      "Regular Expressions")
    (":perl"                    "Regular Expressions")
    (":perlre"                  "Regular Expressions")
    (":exact"                   "Regular Expressions")
    (":ex"                      "Regular Expressions") 
    (":scase"                   "Regular Expressions") 
    (":icase"                   "Regular Expressions")
    (":basic"                   "Regular Expressions")
    (":extended"                "Regular Expressions")
    ("regex"                    "Regular Expressions")))

(defun anubis-describe-keywords ()
  "Depending on the context invoke the appropriate info page"
  (interactive)
  (let* ((word (thing-at-point 'word))
	 (elt (assoc word anubis-keyword-nodes))
         (file (if (= (length elt) 3) (nth 2 elt) "anubis"))
         (node (cadr elt)))
    (Info-goto-node (concat "(" file ")" node))
    (if (get-buffer "*info*")
	(switch-to-buffer "*info*"))))

(defconst anubis-block-dict
  '((if . fi)
    (trigger . done)
    (rule . done)))

(defun anubis-locate-context (&optional keywords)
  (save-excursion
    (let ((rev-keywords (and keywords
			 (mapcar (lambda (x) (cons (cdr x) (car x)))
				keywords)))
	  (cntl-stack nil)
	  (keylist nil)
	  (stop nil))

      (beginning-of-line)
      (if (and keywords (looking-at "^\\s *\\(\\w+\\).*$"))
	  (let* ((word (intern (buffer-substring (match-beginning 1)
						 (match-end 1))))
		 (blk (assoc word rev-keywords)))
	    (if blk
		(push (cdr blk) cntl-stack))))

      (while (and (not stop)
		  (not (bobp)))
	(forward-line -1)
        (cond
         ((looking-at "^\\s *#.*$")) ; skip comments
	 ((looking-at "^\\s *---\\s *BEGIN\\s *\\(\\w+\\)\\s *---")
	  (let ((sect (intern (buffer-substring (match-beginning 1)
						    (match-end 1)))))
	    (setq keylist (append (list sect) keylist)
		  stop t)))
	 ((looking-at "^\\s *BEGIN\\s *\\(\\w+\\)")
	  (let ((sect (intern (buffer-substring (match-beginning 1)
						    (match-end 1)))))
	    (setq keylist (append (list sect) keylist)
		  stop t)))
	 ((looking-at "^\\s *\\(---\\s *\\)?END\\(\\s *---\\)?")
	  (setq stop (point)))
	 ((and keywords (looking-at "^\\s *\\(\\w+\\).*$"))
	  (let* ((word (intern (buffer-substring (match-beginning 1)
		  				 (match-end 1))))
		 (blk (assoc word rev-keywords)))
	    (cond
	     (blk
	      (push (cdr blk) cntl-stack))
	     ((assoc word keywords)
	      (if (and cntl-stack (equal (car cntl-stack) word))
		  (pop cntl-stack)
		(setq keylist (append (list word) keylist)))))))))
      (cons stop keylist))))

;; Complete a given keyword
(defun anubis-complete-keyword (word &optional prompt require-match)
  (let ((dict anubis-keyword-dict)
	(ctx (anubis-locate-context anubis-block-dict)))
    (if (not (car ctx))
	nil
      (let ((dict (assoc (cadr ctx) dict)))
	(if dict
	    (let ((compl (completing-read (or prompt "what? ")
					  (mapcar
					   (lambda (x)
					     (cons (symbol-name (if (listp x)
								    (car x)
								  x))
						   nil))
					   (cdr dict))
					  nil require-match word nil)))
	      (or compl word)))))))
  

(defun anubis-shift-amount ()
  (let ((keylist (anubis-locate-context anubis-block-dict))
	(nesting-level (function (lambda (klist)
			 (let ((len (length klist)))
			   (if (and klist
				    (equal (car klist) 'if)
				    (save-excursion
				      (beginning-of-line)
				      (looking-at "\\s *else")))
			       (1- len)
			     len))))))
    (cond
     ((or (not keylist) (numberp (car keylist)))
      0)
     ((car keylist)
      (+ anubis-section-body-indent
	 (* (funcall nesting-level (cddr keylist)) anubis-level-indent)))
     (t
      (* (funcall nesting-level (cdr keylist)) anubis-level-indent)))))

(defun anubis-indent-line ()
  (let* ((start-of-line (save-excursion
                          (beginning-of-line)
                          (skip-syntax-forward "\\s *")
                          (point)))
         (off (- (point) start-of-line))
         (shift-amt (anubis-shift-amount)))
    (if (null shift-amt)
        ()
      (beginning-of-line)
      (delete-region (point) start-of-line)
      (indent-to shift-amt))
      (goto-char (+ (point) off))))

(defun anubis-complete-or-indent (arg)
  "Complete the keyword the point stays on or indent the current line"
  (interactive "p")
  (let* ((here (point))
         (off 0)
         (bound (save-excursion
                  (beginning-of-line)
                  (point))))
    (if (and
	 (or (eolp) (looking-at "\\s "))
	 (search-backward-regexp "^\\s *\\(\\w+\\)" bound t))
	 
	(let* ((from (match-beginning 1))
                (to (match-end 1))
                (word (buffer-substring from to)))
          (if (= to here)
              ;; Process a keyword
              (let ((compl (anubis-complete-keyword word "keyword: ")))
                (cond
                 ((and compl (not (string-equal compl word)))
                  (delete-region from to)
                  (goto-char from)
                  (insert compl)
                  (setq off (- (point) here)))))
            ;; FIXME: Process the argument
	    )
          (goto-char (+ here off)) )
      (anubis-indent-line) )))


(defun anubis-check-syntax (arg)
  "Checks the syntax of the current Anubis RC buffer. Optional argument
specifies the detail level (from 0 to 3)."
  (interactive "p")
  (compile (concat
	    (if anubis-path anubis-path "anubis")
	    " --check="
	    (number-to-string (or current-prefix-arg 0))
	    " --norc --relax --altrc "
	    (buffer-file-name))))



;;;###autoload
(defun anubis-mode ()
  "Major mode for editing GNU Anubis configuration files.

Key bindings:
\\{anubis-mode-map}
"
  (interactive)
  (kill-all-local-variables)
  (set-syntax-table anubis-mode-syntax-table)
  (make-local-variable 'indent-line-function)
  (set (make-local-variable 'compile-command) "")
  (setq major-mode 'anubis-mode
        mode-name "Anubis-Config"
        local-abbrev-table anubis-mode-abbrev-table
        indent-line-function 'anubis-indent-line
        completion-ignore-case t)

  (use-local-map anubis-mode-map)
  
  (make-local-variable 'font-lock-defaults)
  (setq font-lock-defaults
        '((anubis-font-lock-keywords)
          nil t (("+-*/.<>=!?$%_&~^:" . "w")) beginning-of-defun
          (font-lock-mark-block-function . mark-defun))) )

(require 'info) 
(provide 'anubis-mode)
;;; anubis-mode ends
