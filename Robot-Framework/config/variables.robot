# SPDX-FileCopyrightText: 2022-2023 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Library    OperatingSystem


*** Variables ***

${BUILD_ID}       ${EMPTY}
${SWITCH_TOKEN}   ${EMPTY}
${SWITCH_SECRET}  ${EMPTY}


*** Keywords ***

Set Variables
    [Arguments]  ${device}

    ${config}=     Read Config
    Set Global Variable  ${SERIAL_PORT}        ${config['addresses']['${DEVICE}']['serial_port']}
    Set Global Variable  ${DEVICE_IP_ADDRESS}  ${config['addresses']['${DEVICE}']['device_ip_address']}
    Set Global Variable  ${SOCKET_IP_ADDRESS}  ${config['addresses']['${DEVICE}']['socket_ip_address']}
    Set Global Variable  ${PLUG_TYPE}          ${config['addresses']['${DEVICE}']['plug_type']}
    Set Global Variable  ${THREADS_NUMBER}     ${config['addresses']['${DEVICE}']['threads']}
    Set Global Variable  ${NETVM_NAME}         net-vm
    Set Global Variable  ${NETVM_SERVICE}      microvm@${NETVM_NAME}.service
    Set Global Variable  ${NETVM_IP}           192.168.101.1
    Set Global Variable  ${GUI_VM}             gui-vm.ghaf        # 192.168.100.2
    Set Global Variable  ${CHROMIUM_VM}        chromium-vm.ghaf   # 192.168.100.4
    Set Global Variable  ${GALA_VM}            gala-vm.ghaf       # 192.168.100.3
    Set Global Variable  ${ZATHURA_VM}         zathura-vm.ghaf    # 192.168.100.5

    IF  $BUILD_ID != '${EMPTY}'
        ${config}=     Read Config  ../config/${BUILD_ID}.json
        Set Global Variable    ${JOB}    ${config['Job']}
    END


Read Config
    [Arguments]  ${file_path}=../config/test_config.json

    ${file_data}=    OperatingSystem.Get File    ${file_path}
    TRY
        ${source_data}=    Evaluate    json.loads('''${file_data}''')    json
    EXCEPT
        FAIL    Couldn't parse test config ${file_path}
    END

    RETURN  ${source_data}
