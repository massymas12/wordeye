/*
   WordEye — PHP / WordPress web-shell YARA rules
   SPDX-License-Identifier: MIT
   Authored for WordEye; no third-party ruleset is vendored here (see README
   for loading external packs and their licence terms).

   Design note: rules are composed from COMPONENT strings combined in the
   condition, rather than matching one canonical one-liner. Two reasons.

   1. Resilience. Attackers repack shells until a literal signature stops
      firing, but they cannot remove the primitives — the shell still needs an
      input source, a decoder, and an execution sink. Requiring co-occurrence
      of the components survives reordering, renaming and whitespace games that
      defeat a fixed-string signature.
   2. Hygiene. A rule file containing live canonical one-liners is itself
      flagged and quarantined by endpoint protection on the analyst's machine.

   Severity is expressed via meta.severity: critical | high | medium | low.
*/

private rule is_php
{
    strings:
        $open  = "<?php" nocase
        $short = "<?="
    condition:
        any of them
}

rule php_shell_input_to_exec
{
    meta:
        description = "PHP file routes request input directly into an execution sink"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $in1 = "$_POST"    ascii
        $in2 = "$_GET"     ascii
        $in3 = "$_REQUEST" ascii
        $in4 = "$_COOKIE"  ascii
        $in5 = "php://input" ascii nocase

        $ex1 = "eval"        ascii nocase fullword
        $ex2 = "assert"      ascii nocase fullword
        $ex3 = "shell_exec"  ascii nocase fullword
        $ex4 = "passthru"    ascii nocase fullword
        $ex5 = "proc_open"   ascii nocase fullword
        $ex6 = "popen"       ascii nocase fullword
        $ex7 = "pcntl_exec"  ascii nocase fullword
    condition:
        // Proximity, not co-occurrence. A superglobal on line 200 and an
        // eval() on line 4,000 are two unrelated facts about a large plugin;
        // a shell puts the input INSIDE the call.
        is_php and near(($in*), ($ex*), 250) and filesize < 300KB
}

rule php_shell_obfuscated_loader
{
    meta:
        description = "Decoder chained into an execution sink — payload hidden from inspection"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $d1 = "base64_decode"    ascii nocase
        $d2 = "gzinflate"        ascii nocase
        $d3 = "gzuncompress"     ascii nocase
        $d4 = "str_rot13"        ascii nocase
        $d5 = "convert_uudecode" ascii nocase
        $d6 = "hex2bin"          ascii nocase
        $d7 = "gzdecode"         ascii nocase

        $e1 = "eval"            ascii nocase fullword
        $e2 = "assert"          ascii nocase fullword
        $e3 = "create_function" ascii nocase fullword
        // preg_replace is deliberately absent. Its /e modifier — the only form
        // that executed anything — was removed in PHP 7, so a bare
        // preg_replace is ordinary string handling present in nearly every
        // large plugin. Listing it here made this rule fire on Wordfence,
        // Gravity Forms, ACF and Divi. The surviving legacy case has its own
        // rule: php_preg_replace_eval_modifier.
    condition:
        // The decoder must feed the sink, e.g. eval(gzinflate(base64_decode(…))).
        // Requiring only that both appear somewhere in the file matches any
        // plugin that base64-encodes an asset and calls eval elsewhere.
        is_php and 2 of ($d*) and near(($d*), ($e*), 200) and filesize < 500KB
}

rule php_shell_dynamic_dispatch
{
    meta:
        description = "Function name supplied by the request (dynamic-dispatch shell)"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $a = /\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[^\]]{0,80}\]\s*\(/
        $b = /\$\{\s*\$[a-zA-Z_]\w*\s*\}\s*\(/
        $c = /\$GLOBALS\s*\[[^\]]{1,40}\]\s*\(/
    condition:
        is_php and any of them
}

rule php_shell_password_gate
{
    meta:
        description = "Request parameter compared against a stored hash — an authenticated web shell"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $h1 = "md5"           ascii nocase fullword
        $h2 = "sha1"          ascii nocase fullword
        $h3 = "crypt"         ascii nocase fullword
        $h4 = "password_verify" ascii nocase fullword
        $hex = /[\x22\x27][a-f0-9]{32,64}[\x22\x27]/
        $in1 = "$_POST"    ascii
        $in2 = "$_GET"     ascii
        $in3 = "$_REQUEST" ascii
        $in4 = "$_COOKIE"  ascii
        $ex = /\b(eval|assert|system|shell_exec|passthru)\b/ nocase
    condition:
        // A password gate is a tight construct: the hash literal, the request
        // parameter and the hashing call sit together. Spread across a file,
        // these four terms describe any plugin that stores a hash and reads a
        // form — which is most of them.
        is_php and near(($hex), ($in*), 300)
              and near(($hex), ($h*), 300)
              and $ex and filesize < 300KB
}

rule php_shell_file_manager
{
    meta:
        description = "Browser-based file manager: the operator UI of a web shell"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $u1 = "move_uploaded_file" ascii nocase
        $u2 = "$_FILES"            ascii
        $f1 = "opendir"            ascii nocase fullword
        $f2 = "readdir"            ascii nocase fullword
        $f3 = "scandir"            ascii nocase fullword
        $f4 = "unlink"             ascii nocase fullword
        $f5 = "rename"             ascii nocase fullword
        $f6 = "chmod"              ascii nocase fullword
        $x1 = "shell_exec" ascii nocase
        $x2 = "passthru"   ascii nocase
        $x3 = "popen"      ascii nocase
        $form = "<form" nocase
    condition:
        is_php and all of ($u*) and 3 of ($f*) and any of ($x*) and $form
}

rule php_reverse_shell
{
    meta:
        description = "Outbound socket paired with an execution primitive (reverse shell)"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $s1 = "fsockopen"    ascii nocase fullword
        $s2 = "socket_create" ascii nocase fullword
        $s3 = "stream_socket_client" ascii nocase fullword
        $e1 = "proc_open"  ascii nocase fullword
        $e2 = "shell_exec" ascii nocase fullword
        $e3 = "passthru"   ascii nocase fullword
        $e4 = "popen"      ascii nocase fullword
        $d1 = "/bin/sh"  ascii
        $d2 = "/bin/bash" ascii
        $d3 = "descriptorspec" ascii nocase
    condition:
        is_php and any of ($s*) and any of ($e*) and any of ($d*)
}

rule php_packed_payload_blob
{
    meta:
        description = "Very long encoded blob inside a small PHP file — packed payload"
        severity    = "high"
        author      = "WordEye"
    strings:
        $blob = /[A-Za-z0-9+\/]{600,}={0,2}/
        $d1 = "base64_decode" ascii nocase
        $d2 = "gzinflate"     ascii nocase
        $d3 = "str_rot13"     ascii nocase
        $d4 = "gzuncompress"  ascii nocase
    condition:
        is_php and $blob and any of ($d*) and filesize < 2MB
}

rule php_char_assembly_obfuscation
{
    meta:
        description = "Identifier assembled character-by-character to defeat literal matching"
        severity    = "high"
        author      = "WordEye"
    strings:
        $chain = /(chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*){6,}/ nocase
        $hexrun = /(\\x[0-9a-fA-F]{2}){12,}/
        $concat = /[\x22\x27]\s*\.\s*[\x22\x27][a-z]{1,3}[\x22\x27]\s*\.\s*[\x22\x27]/
        $sink = /\b(eval|assert|system|exec|shell_exec|passthru|create_function)\b/ nocase
    condition:
        is_php and any of ($chain, $hexrun, $concat) and $sink
}

rule php_preg_replace_eval_modifier
{
    meta:
        description = "preg_replace with the /e modifier — evaluates the replacement as PHP"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $a = /preg_replace\s*\(\s*[\x22\x27][^\x22\x27]{0,200}\/[a-zA-Z]{0,6}e[a-zA-Z]{0,6}[\x22\x27]\s*,/ nocase
    condition:
        is_php and $a
}

rule php_antianalysis_shell
{
    meta:
        description = "Error suppression and timeout removal alongside an execution sink"
        severity    = "high"
        author      = "WordEye"
    strings:
        $a1 = "error_reporting(0"  ascii nocase
        $a2 = "set_time_limit(0"   ascii nocase
        $a3 = "ignore_user_abort"  ascii nocase
        $a4 = "@ini_set"           ascii nocase
        $a5 = "disable_functions"  ascii nocase
        $sink = /\b(eval|assert|shell_exec|passthru|proc_open|system)\b/ nocase
        $in   = /\$_(GET|POST|REQUEST|COOKIE)/
    condition:
        is_php and 2 of ($a*) and $sink and $in and filesize < 300KB
}

rule wp_backdoor_admin_creation
{
    meta:
        description = "Request-triggered WordPress administrator creation"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $w1 = "wp_create_user"  ascii nocase
        $w2 = "wp_insert_user"  ascii nocase
        $r1 = "set_role"        ascii nocase
        $r2 = "add_role"        ascii nocase
        $r3 = "administrator"   ascii nocase
        $in = /\$_(GET|POST|REQUEST|COOKIE)/

        // Capability and nonce checks. An attacker does not gate their own
        // persistence behind the permission system they are subverting, so a
        // check adjacent to the creation call marks an admin feature — which is
        // what wordpress-importer and Divi's SupportCenter actually are.
        $cap1 = "current_user_can"    ascii nocase
        $cap2 = "check_admin_referer" ascii nocase
        $cap3 = "wp_verify_nonce"     ascii nocase
        $cap4 = "check_ajax_referer"  ascii nocase
    condition:
        // Legitimate importers and support tools create privileged users too;
        // what distinguishes a backdoor is that the request input, the role and
        // the creation call are one construct rather than three features of a
        // large plugin.
        is_php and near(($w*), ($in), 400) and near(($w*), ($r*), 400)
               and not near(($w*), ($cap*), 400)
}

rule wp_backdoor_auth_bypass
{
    meta:
        description = "Authentication cookie minted directly from request input — silent admin login"
        severity    = "critical"
        author      = "WordEye"
    strings:
        // The superglobal must be INSIDE the call's own parentheses, not merely
        // somewhere nearby.
        //
        // Proximity alone was far too loose. Calling wp_set_auth_cookie with a
        // user id the plugin resolved itself is what every login, membership and
        // SSO plugin does for a living, and a $_POST redirect parameter twenty
        // lines away is not evidence of anything. A field estate reported
        // ProfilePress's own auto-login feature as a critical backdoor on that
        // basis, alongside five PHPUnit fixtures.
        //
        // What distinguishes a backdoor is that the identity being authenticated
        // comes from the request: wp_set_auth_cookie($_GET['uid']).
        $direct = /wp_set_(auth_cookie|current_user)\s*\(\s*[^;]{0,80}\$_(GET|POST|REQUEST|COOKIE)/ nocase
    condition:
        is_php and $direct
}

rule wp_auth_call_near_request_input
{
    meta:
        description = "Authentication call in a function that also reads request input — review the data flow"
        severity    = "medium"
        author      = "WordEye"
    strings:
        $a = "wp_set_auth_cookie" ascii nocase
        $b = "wp_set_current_user" ascii nocase
        $in = /\$_(GET|POST|REQUEST|COOKIE)/
    condition:
        // The old proximity test, kept at a severity that matches what it
        // actually proves. Worth surfacing — an auth call beside request input
        // deserves a human read — but it is not on its own a backdoor.
        is_php and near(($a, $b), ($in), 300) and not wp_backdoor_auth_bypass
}

rule wp_seo_cloak_crawler_switch
{
    meta:
        description = "Content varies by crawler user-agent — SEO cloaking"
        severity    = "high"
        author      = "WordEye"
    strings:
        $ua  = "HTTP_USER_AGENT" ascii nocase
        $c1  = "googlebot" ascii nocase
        $c2  = "bingbot"   ascii nocase
        $c3  = "yandex"    ascii nocase
        $c4  = "slurp"     ascii nocase
        $f1  = "file_get_contents" ascii nocase
        $f2  = "curl_exec"  ascii nocase
        $f3  = "header("    ascii nocase
        $f4  = "readfile"   ascii nocase
    condition:
        is_php and $ua and any of ($c*) and any of ($f*)
}

rule php_spam_mailer
{
    meta:
        description = "Bulk mail driven by request input — spam relay"
        severity    = "high"
        author      = "WordEye"
    strings:
        // fullword matters enormously here: without it this substring also
        // matches wp_mail( — WordPress's own wrapper, and what every legitimate
        // plugin calls. That alone flagged Gravity Forms' notification code,
        // Divi's contact form, Wordfence and simple-history. A relay calls the
        // raw PHP mail() precisely because it is bypassing the platform.
        $m1 = "mail(" ascii nocase fullword
        $in = /\$_(GET|POST|REQUEST)/
        $l1 = "foreach" ascii nocase fullword
        $l2 = "while"   ascii nocase fullword
    condition:
        // PHPMailer and an HTML content-type were dropped as alternates: both
        // are ordinary in any plugin that sends mail at all. What distinguishes
        // a relay is that the send, the loop and the attacker-controlled
        // recipient sit together in one construct.
        is_php
        and near(($m1), ($in), 300)
        and near(($m1), ($l1, $l2), 300)
        and filesize < 200KB
}

rule php_dropper_writes_executable
{
    meta:
        description = "Writes a PHP file whose content arrives in the request"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $w1 = "file_put_contents" ascii nocase
        $w2 = "fwrite"            ascii nocase fullword
        $p  = /[\x22\x27]\.ph(p|tml)[0-9]?[\x22\x27]/ nocase
        $in = /\$_(GET|POST|REQUEST|COOKIE|FILES)/
    condition:
        is_php and any of ($w*) and $p and $in and filesize < 300KB
}

rule php_polyglot_asset
{
    meta:
        description = "Valid image header followed by PHP source — upload-filter bypass"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $jpg = { FF D8 FF }
        $gif = "GIF8"
        $php = "<?php" nocase
    condition:
        ($png at 0 or $jpg at 0 or $gif at 0) and $php
}

rule php_hidden_in_htaccess_scope
{
    meta:
        description = "Handler directive that makes non-PHP files execute as PHP"
        severity    = "critical"
        author      = "WordEye"
    strings:
        $a1 = "AddType application/x-httpd-php" nocase
        $a2 = "AddHandler" nocase
        $a3 = "SetHandler application/x-httpd-php" nocase
        $a4 = "auto_prepend_file" nocase
        $a5 = "php_flag engine on" nocase
    condition:
        // These are server-configuration directives, so this rule belongs to
        // .htaccess / .user.ini / php.ini — never to PHP source. Without the
        // guard it fired on any PHP file that merely NAMES a directive, which
        // includes Wordfence's own WAF bootstrap (it configures
        // auto_prepend_file legitimately) and its deactivation UI.
        any of them and not is_php and filesize < 64KB
}
