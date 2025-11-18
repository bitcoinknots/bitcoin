(define-module (bitcoin-knots)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix git-download)
  #:use-module (guix build-system cmake)
  #:use-module (guix gexp)
  #:use-module (guix utils)
  #:use-module (gnu packages)
  #:use-module (gnu packages bash)
  #:use-module (gnu packages base)
  #:use-module (gnu packages boost)
  #:use-module (gnu packages libevent)
  #:use-module (gnu packages networking)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages python)
  #:use-module (gnu packages python-xyz)
  #:use-module (gnu packages sqlite))

(define-public bitcoin-knots
  (package
    (name "bitcoin-knots")
    (version (getenv "VERSION"))
    ; the source section is overrided by the guix-build script
    (source (origin
              (method git-fetch)
              (uri (git-reference
                    (url "https://github.com/bitcoinknots/bitcoin")
                    (commit (string-append "v" version))))
              ; We use a fake hash because this scheme isn't supposed
              ; to be builded outside the guix-build scipt
              (sha256 #f)))
    (build-system cmake-build-system)
    (arguments
     (list #:configure-flags
           #~(list
              "-DBUILD_GUI=OFF"
              "-DBUILD_TESTS=ON"
              "-DWITH_ZMQ=ON")
           #:phases
           #~(modify-phases %standard-phases
               (add-before 'build 'set-no-git-flag
                 (lambda _
                   ;; Make it clear we are not building from within a git repository
                   ;; (and thus no information regarding this build is available
                   ;; from git).
                   (setenv "BITCOIN_GENBUILD_NO_GIT" "1")))
               (add-before 'check 'set-home
                 (lambda _
                   ;; Tests write to $HOME.
                   (setenv "HOME" (getenv "TMPDIR")))))))
    (native-inputs
     (list bash ; provides the sh command for system_tests
           coreutils ; provides the cat, echo and false commands for system_tests
           pkg-config
           python ; for the tests
           python-pyzmq ; for the tests
           ))
    (inputs
     (list boost
           libevent
           sqlite
           zeromq))
    (home-page "https://bitcoinknots.org/")
    (synopsis "Bitcoin peer-to-peer client")
    (description
     "Bitcoin is a digital currency that enables instant payments to anyone
anywhere in the world.  It uses peer-to-peer technology to operate without
central authority: managing transactions and issuing money are carried out
collectively by the network.  This package provides the Bitcoin Knots command
line client.")
    (license license:expat)))

bitcoin-knots
