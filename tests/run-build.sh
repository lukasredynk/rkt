#!/usr/bin/env bash

set -ex

function cleanup {
    if [[ "${POSTCLEANUP}" == true ]]; then
        for mp in $(mount | grep rkt | awk '{print $3}' | tac); do
            sudo umount "${mp}"
        done

        for link in $(ip link | grep rkt | cut -d':' -f2); do
            sudo ip link del "${link}"
        done
        sudo rm -rf /var/lib/cni/networks/*
    fi
    sudo rm -rf "${BUILD_DIR}"
}

function ciSkip {
    cat last-commit
    echo
    echo "Build skipped as requested in the last commit."
    exit 0
}

function semaphoreConfiguration {
    # We might not need to run functional tests or process docs.
    # This is best-effort; || true ensures this does not affect test outcome
    # First, ensure origin is updated - semaphore can do some weird caching
    git fetch || true
    SRC_CHANGES=$(git diff-tree --no-commit-id --name-only -r HEAD..origin/master | grep -cEv ${DOC_CHANGE_PATTERN}) || true
    DOC_CHANGES=$(git diff-tree --no-commit-id --name-only -r HEAD..origin/master | grep -cE ${DOC_CHANGE_PATTERN}) || true

    # Set up go environment on semaphore
    if [ -f /opt/change-go-version.sh ]; then
        . /opt/change-go-version.sh
        change-go-version 1.5
    fi
}

function parseParameters {
    while getopts ":f:s:c" option; do
        case ${option} in
        f)
            RKT_STAGE1_USR_FROM="${OPTARG}"
            ;;
        s)
            RKT_STAGE1_SYSTEMD_VER="${OPTARG}"
            ;;
        c)
            PRECLEANUP=true
            POSTCLEANUP=true
            ;;
        \?)
            echo "Invalid parameter -${OPTARG}"
            exit 1
            ;;
        esac
    done
}

function configure {
    case "${RKT_STAGE1_USR_FROM}" in
        coreos|kvm)
        ./configure --with-stage1-flavors="${RKT_STAGE1_USR_FROM}" \
                --with-stage1-default-flavor="${RKT_STAGE1_USR_FROM}" \
                --enable-functional-tests --enable-tpm=auto \
                --enable-insecure-go
        ;;
        host)
        ./configure --with-stage1-flavors=host \
                --with-default-stage1-flavor=host \
                --enable-functional-tests=auto --enable-tpm=auto \
                --enable-insecure-go
        ;;
        src)
        ./configure --with-stage1-flavors="${RKT_STAGE1_USR_FROM}" \
                --with-stage1-default-flavor="${RKT_STAGE1_USR_FROM}" \
                --with-stage1-systemd-version="${RKT_STAGE1_SYSTEMD_VER}" \
                --enable-functional-tests --enable-tpm=auto \
                --enable-insecure-go
        ;;
        none)
        # Not a flavor per se, so perform a detailed setup for some
        # hypothetical 3rd party stage1 image
        ./configure --with-stage1-default-name="example.com/some-stage1-for-rkt" \
                --with-stage1-default-version="0.0.1" --enable-tpm=auto \
                --enable-insecure-go
        ;;
        *)
        echo "Unknown flavor: ${RKT_STAGE1_USR_FROM}"
        exit 1
        ;;
    esac
}

function build {
    ./autogen.sh

    configure

    CORES=$(grep -c ^processor /proc/cpuinfo)
    echo "Running make with ${CORES} threads"
    make "-j${CORES}"

    if [[ ${PRECLEANUP} == true ]]; then
        rm -rf "${BUILD_DIR}/tmp/usr_from_${RKT_STAGE1_USR_FROM}"
    fi

    make check
    make "-j${CORES}" clean
}

function buildFolder {
    if [[ "${RKT_STAGE1_USR_FROM}" == 'systemd' ]]; then
        POSTFIX="-${RKT_STAGE1_SYSTEMD_VER}"
    fi
    BUILD_DIR="build-rkt-${RKT_STAGE1_USR_FROM}${POSTFIX}"
}

function detectChanges {
    HEAD=`git rev-parse HEAD`
    MASTER=`git rev-parse origin/master`
    if [[ ${HEAD} != ${MASTER} ]]; then
        SRC_CHANGES=1
        DOC_CHANGES=1
    elif [[ ${SRC_CHANGES} -eq 0 && ${DOC_CHANGES} -eq 0 ]]; then
        echo "No changes detected and HEAD is not origin/master"
        exit 0
    fi
}

function cloneCode {
    detectChanges
    git clone ../ "${BUILD_DIR}"
    pushd "${BUILD_DIR}"
}

function prepareBuildEnv {
    # In case it wasn't cleaned up
    if [ -e "builds/${BUILD_DIR}" ]; then
        sudo rm -rf "builds/${BUILD_DIR}"
    fi
    mkdir -p builds
}

function docsScan {
    :
    # echo Changes in docs detected, checking docs.
    # TODO check for broken links
    # TODO check for obvious spelling mistakes:
        # coreos -> CoreOS
        # More?!
}

function main {
    # Skip build if requested
    if test -e ci-skip ; then
        ciSkip
    fi

    SRC_CHANGES=1 # run functional tests by default
    DOC_CHANGES=1 # process docs by default
    DOC_CHANGE_PATTERN="\
            -e ^Documentation/ \
            -e ^(README|ROADMAP|CONTRIBUTING|CHANGELOG)$ \
            -e \.md$\
    "

    parseParameters "${@}"
    buildFolder

    # https://semaphoreci.com/docs/available-environment-variables.html
    if [ "${SEMAPHORE-}" == true ] ; then
        semaphoreConfiguration
    fi

    prepareBuildEnv
    cd builds
    cloneCode

    if [ ${SRC_CHANGES} -gt 0 ]; then
        build
    fi
    if [ ${DOC_CHANGES} -gt 0 ]; then
        docsScan
    fi
    cleanup
}

main "${@}"
