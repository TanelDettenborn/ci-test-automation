# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Test OP-TEE PKCS#11 through pkcs11-tool wrappers
Resource            ../../resources/ssh_keywords.resource
Resource            ../../config/variables.robot
Suite Setup         Connect
Suite Teardown      Close All Connections


*** Test Cases ***


OP-TEE xtest
       [Documentation]  Runs OP-TEE's xtest
       ...
       ...              NOTE: About fail and failures!!
       ...              As a background then currently three test cases are failing within
       ...              xtest full run and therefore these test cases are excluded from
       ...              full run. They fail due bug/issues within OP-TEE. As soon as fixes
       ...              are introduced then xtest-test suite should be updated!
       ...
       ...              If one of the "Expect failure from xtest XXXX" test success then:
       ...
       ...              1. Remove corresponding "-n"-flag from full xtest run
       ...
       ...              2. Delete corresponding Expect failure from xtest XXXX" test case
       ...
       ...              If everything fixed (no more "-n"-flags), remove this comment!!
       [Tags]  optee-xtest

       Full xtest
       Expect failure from xtest 1008
       Expect failure from xtest 1033
       Expect failure from xtest 4016_ed25519


Basic pkcs11-tool-optee test
    [Documentation]   Test OP-TEE PKCS#11 through pkcs11-tool-optee wrapper.
    ...               Basic test which initalizes key slots, by directly
    ...               calling OP-TEE.
    [Tags]            optee  SP-T666  orin-agx  orin-nx

    ${tool}=    Set Variable    "pkcs11-tool-optee"
    List key slots    ${tool}
    Initialize slot    ${tool}
    Test Public Key usage    ${tool}    keyid=1    keylabel=rsakey0    mechanism=SHA256-RSA-PKCS-PSS
    Test Public Key usage    ${tool}    keyid=2    keylabel=eckey0    mechanism=ECDSA-SHA256
    List key slots    ${tool}
    List objects    ${tool}

# These two tests are for the ghaf-caml-crush, which is not included in the
# default build, but the tests are included here for convenience.

Check caml-crush service is running
    [Documentation]  Checks if the systemd service for caml-crush is running.
    # Tags should be really: optee orin-agx  orin-nx
    # but caml-crush is not included in basic ghaf builds
    [Tags]  caml-crush

    ${status}  ${state}=    Verify service status  service="caml-crush.service"  expected_status=active  expected_state=running


Basic pkcs11-tool-caml-crush test
    [Documentation]   Test OP-TEE PKCS#11 through pkcs11-tool-caml-crush
    ...               wrapper. Basic test which initalizes key slots, by
    ...               calling OP-TEE through caml-crush's pkcs11proxyd.
    # Tags should be really: optee  orin-agx  orin-nx
    # but caml-crush is not included in basic ghaf builds
    [Tags]  caml-crush

    ${tool}=    Set Variable    "pkcs11-tool-caml-crush-optee"
    List key slots    ${tool}
    Initialize slot    ${tool}
    Test Public Key usage    ${tool}    keyid=1    keylabel=rsakey0    mechanism=SHA256-RSA-PKCS-PSS
    Test Public Key usage    ${tool}    keyid=2    keylabel=eckey0    mechanism=ECDSA-SHA256
    List key slots    ${tool}
    List objects    ${tool}


*** Keywords ***

Full xtest
    [Documentation]   Runs all OP-TEE's xtest
    ...
    ...               NOTE About fail: Test suite comment!!

    ${stdout}    ${stderr}    ${rc}=    Execute Command    xtest -x 1008 -x 1033 -x 4016_ed25519    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Log     ${stdout}
    Should Be Equal As Integers    ${rc}    0


Expect failure from xtest 1008
    [Documentation]   Expects failure from 1008.
    ...
    ...               NOTE About fail: Test suite comment!!
    ...
    ...               Fix: xtest TA load path wrong

    ${stdout}    ${stderr}    ${rc}=    Execute Command    xtest 1008   sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    1

Expect failure from xtest 1033
    [Documentation]   Expects failure from 1033.
    ...
    ...               NOTE About fail: Test suite comment!!
    ...
    ...               Fix: OP-TEE requires plugin load path

    ${stdout}    ${stderr}    ${rc}=    Execute Command    xtest 1033   sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    1

Expect failure from xtest 4016_ed25519
    [Documentation]   Expects failure from 4016_ed25519.
    ...
    ...               NOTE About fail: Test suite comment!!
    ...
    ...               Fix: OP-TEE requires patch: https://github.com/OP-TEE/optee_os/commit/e4c24b7f9f1afbdd7a48766007cf0055b4b8df6b

    ${stdout}    ${stderr}    ${rc}=    Execute Command    xtest 4016_ed25519   sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    1


List key slots
    [Documentation]    List all key slots
    [Arguments]        ${tool}

    ${cmd}=    Set Variable    ${tool} -L
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0


List objects
    [Documentation]    List all key slots
    [Arguments]        ${tool}

    ${cmd}=    Set Variable    ${tool} --list-objects
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0


Initialize slot
    [Documentation]    Initialize Key Slot
    [Arguments]        ${tool}

    ${cmd}=    Set Variable    ${tool} --init-token --label mytoken --so-pin 1234
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0

    ${cmd}=    Set Variable    ${tool} --label mytoken --login --so-pin 1234 --init-pin --pin 0000
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0

    ${cmd}=    Set Variable    ${tool} --token-label mytoken --pin 0000 --keypairgen --key-type RSA:2048 --id 1 --label rsakey0
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0

    ${cmd}=    Set Variable    ${tool} --token-label mytoken --pin 0000 --keypairgen --key-type EC:secp256r1 --id 2 --label eckey0
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0


Test Public Key usage
    [Documentation]    Test Public Key usage
    [Arguments]        ${tool}    ${keyid}    ${keylabel}    ${mechanism}

    ${content_file}=    Set Variable    /tmp/pkcs11test_content
    ${signature_file}=    Set Variable    /tmp/pkcs11test_signature

    ${cmd}=    Set Variable    dd if=/dev/random of=${content_file} count=1 bs=32
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0

    ${cmd}=    Set Variable    ${tool} --token-label mytoken --pin 0000 --id ${keyid} --label ${keylabel} --sign -m ${mechanism} --input-file ${content_file} --output-file ${signature_file}
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0

    ${cmd}=    Set Variable    ${tool} --token-label mytoken --pin 0000 --id ${keyid} --label ${keylabel} --verify -m ${mechanism} --signature-file ${signature_file} --input-file ${content_file}
    ${stdout}    ${stderr}    ${rc}=    Execute Command    ${cmd}    sudo=True    sudo_password=${PASSWORD}    return_stdout=True    return_stderr=True    return_rc=True
    Should Be Equal As Integers    ${rc}    0
    Should Contain    ${stdout}    Signature is valid
    Should Not Contain    ${stdout}    Invalid signature
