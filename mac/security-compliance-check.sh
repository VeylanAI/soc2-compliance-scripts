#!/bin/bash

# ==============================================================================
# SOC 2 UNIVERSAL SECURITY CHECK
# Compatible with: macOS High Sierra (10.13) through macOS Sequoia (15.x)
# Checks: Gatekeeper, SIP, and XProtect (Smart Path Detection)
# ==============================================================================

# --- 1. CHECK GATEKEEPER ---
gk_status=$(spctl --status 2>&1)
if [[ "$gk_status" == *"assessments enabled"* ]]; then
    gk_result="Enabled"
else
    gk_result="Disabled"
fi

# --- 2. CHECK SIP (System Integrity Protection) ---
sip_status=$(csrutil status)
if [[ "$sip_status" == *"enabled"* ]]; then
    sip_result="Enabled"
else
    sip_result="Disabled"
fi

# --- 3. CHECK XPROTECT (Smart Detection) ---
# XProtect location has changed 3 times. We check them in order of newest to oldest.

# PATH A: macOS Sequoia (15.x) and newer
# Sequoia introduced a dedicated 'xprotect' command line tool.
if [[ -x "/usr/bin/xprotect" ]]; then
    # specific command to get version in Sequoia
    xp_ver=$(/usr/bin/xprotect version 2>/dev/null | awk '{print $2}')
    if [ ! -z "$xp_ver" ]; then
        xprotect_result="Active (v$xp_ver)"
    fi
fi

# PATH B: Modern macOS (Catalina 10.15 - Sonoma 14.x)
# If Path A didn't work, check the modern file path in /Library/Apple
if [ -z "$xprotect_result" ]; then
    if [ -f "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist" ]; then
        xp_ver=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version 2>/dev/null)
        if [ ! -z "$xp_ver" ]; then
            xprotect_result="Active (v$xp_ver)"
        fi
    fi
fi

# PATH C: Legacy macOS (Mojave 10.14 and older)
# If Path A and B failed, check the legacy CoreServices path
if [ -z "$xprotect_result" ]; then
    if [ -f "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist" ]; then
        xp_ver=$(defaults read /System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist Version 2>/dev/null)
        if [ ! -z "$xp_ver" ]; then
            xprotect_result="Active (v$xp_ver)"
        fi
    fi
fi

# Fallback if absolutely nothing was found
if [ -z "$xprotect_result" ]; then
    xprotect_result="Missing/Unknown"
fi

# ==============================================================================
# FINAL OUTPUT
# ==============================================================================

if [[ "$gk_result" == "Enabled" ]] && [[ "$sip_result" == "Enabled" ]] && [[ "$xprotect_result" != "Missing/Unknown" ]]; then
    # For Jamf:
    echo "<result>PASS: All Native Security Active</result>"
    # For Kandji/Intune (uncomment below):
    # echo "PASS: All Native Security Active"
else
    # For Jamf:
    echo "<result>FAIL: Gatekeeper: $gk_result | SIP: $sip_result | XProtect: $xprotect_result</result>"
    # For Kandji/Intune (uncomment below):
    # echo "FAIL: Gatekeeper: $gk_result | SIP: $sip_result | XProtect: $xprotect_result"
fi