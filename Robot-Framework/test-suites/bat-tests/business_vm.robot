# SPDX-FileCopyrightText: 2022-2025 Technology Innovation Institute (TII)
# SPDX-License-Identifier: Apache-2.0

*** Settings ***
Documentation       Testing Business VM
Force Tags          bat   pre-merge  businessvm  lenovo-x1
Resource            ../../resources/ssh_keywords.resource
Resource            ../../resources/virtualization_keywords.resource
Resource            ../../config/variables.robot
Resource            ../../resources/common_keywords.resource

Suite Teardown      Close All Connections


*** Test Cases ***

Start Microsoft Outlook on LenovoX1
    [Documentation]   Start Microsoft Outlook in Business-vm and verify process started
    [Tags]  outlook  SP-T176
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   "Microsoft Outlook"
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    outlook
    [Teardown]  Kill process  @{app_pids}

Start Microsoft 365 on LenovoX1
    [Documentation]   Start Microsoft 365 in Business-vm and verify process started
    [Tags]  microsoft365  SP-T178
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   "Microsoft 365"
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    microsoft365
    [Teardown]  Kill process  @{app_pids}

Start Microsoft Teams on LenovoX1
    [Documentation]   Start Microsoft Teams in Business-vm and verify process started
    [Tags]  teams  SP-T177
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   Teams
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    teams
    [Teardown]  Kill process  @{app_pids}

Start Trusted Browser on LenovoX1
    [Documentation]   Start Trusted Browser in Business-vm and verify process started
    [Tags]  trusted_browser  SP-T179
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   "Trusted Browser"
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    chrome
    [Teardown]  Kill process  @{app_pids}

Start Video Editor on LenovoX1
    [Documentation]   Start Video Editor in Business-vm and verify process started
    [Tags]  video_editor  SP-T244
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   "Video Editor"
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    lossless
    [Teardown]  Kill process  @{app_pids}

Start Text Editor on LenovoX1
    [Documentation]   Start Text Editor in Business-vm and verify process started
    [Tags]  text_editor  SP-T243
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   "Text Editor"
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    text-editor
    [Teardown]  Kill process  @{app_pids}

Start Xarchiver on LenovoX1
    [Documentation]   Start Xarchiver in Business-vm and verify process started
    [Tags]  xarchiver  SP-T242
    Connect to netvm
    Connect to VM       ${GUI_VM}   ${USER_LOGIN}   ${USER_PASSWORD}
    Start XDG application   "Xarchiver"
    Connect to VM       ${BUSINESS_VM}
    Check that the application was started    xarchiver
    [Teardown]  Kill process  @{app_pids}
