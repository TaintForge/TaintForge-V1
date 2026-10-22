#!/usr/bin/env bash
# TaintForge campaign: WordPress core trunk (WordPress/wordpress-develop, 7.2-alpha), white-box
# plus a live local instance at http://wsl.evm.pics:31655.
#
# Every role (A, B, C, D, E) runs on Claude Opus 5.
# Stop: touch workspace/_stop; kill $(cat workspace/_pids); tmux kill-session -t taintforge
set -Eeuo pipefail
cd "$(dirname "$0")"

TARGET="${TARGET:-targets/wordpress-develop}"
URL="${URL:-http://wsl.evm.pics:31655}"
ACCOUNTS="${ACCOUNTS:-.wordpress.accounts.json}"

export TF_BACKEND=claude
export TF_MODEL="${TF_MODEL:-claude-opus-5}"
unset CODEX_CMD CODEX_CMD_A CODEX_CMD_B CODEX_CMD_C CODEX_CMD_D CODEX_CMD_E CODEX_CMD_F || true
export MAX_HOURS="${MAX_HOURS:-24}"
# CODE_MODEL, per-module models, coverage and hypotheses are seeded once by ./seed-wordpress.sh.
export TF_REUSE_SEED="${TF_REUSE_SEED:-1}"

# The canary must be reachable from INSIDE the php container, which is where WordPress runs.
# wsl.evm.pics is a public name that resolves and hairpins correctly from the container, so it
# also survives WordPress's private-IP SSRF filter - that is what makes it the right oracle.
export SSRF_HOST="${SSRF_HOST:-wsl.evm.pics}"
export SSRF_PORT="${SSRF_PORT:-9898}"

export TAINTFORGE_EXTRA_CONTEXT="TARGET-SPECIFIC THREAT MODEL - WordPress core, trunk 7.2-alpha
(WordPress/wordpress-develop @ 10bbb652ec, cloned $(date +%Y-%m-%d)).

===============================================================================
CAMPAIGN FOCUS - READ THIS FIRST. IT OVERRIDES THE DEFAULT PRIORITISATION.
===============================================================================
This campaign has been re-pointed at two vulnerability classes:

  (1) SQL INJECTION                     - Track A owns it, D weaponises it.
  (2) XS-LEAKS / CROSS-SITE ORACLES     - Track B owns it, A takes any parsing half.

Everything below this block - the lab description, the boundary rules, the code model, the
disclosure ladder - still applies unchanged. What changes is your SEARCH ORDER. Spend your
passes here.

Findings outside these two classes are still accepted: if a sweep turns up a confirmed bug of
another class, FILE IT, then get back on focus. Do not go looking for them, and do not re-tread
ground the earlier phase already covered. Already confirmed on this target, do NOT re-report:
Interactivity API data-wp-bind--href kses bypass; REST comments X-WP-Total count oracle;
wp_ajax_find_posts missing capability check; comment moderation queue disclosure;
wp_ajax_oembed_cache missing nonce/capability; wp_insert_user registration race (known).

Read these before you start grepping - they are pre-generated for this phase:
  workspace/hints/track-a-sqli.md      8 sections of real wpdb/prepare call sites, by class
  workspace/hints/track-b-xsleaks.md   preconditions MEASURED on this target, plus the surface
  workspace/hints/track-a-semgrep.md   the general OpenGrep run from the earlier phase

------------------------------------------------------------------------------
(1) SQL INJECTION - what is actually still reachable in WordPress core in 2026
------------------------------------------------------------------------------
Raw string interpolation into a query is nearly extinct here, and WPCS has swept the obvious
cases. Do not waste passes grepping for \$wpdb->query(\"... \$var ...\"); you will find only
admin-only schema code with no attacker-controlled input. The live classes are these:

  a. FORMAT-STRING INJECTION INTO prepare(). This is the top lane. When the first argument to
     prepare() is a VARIABLE rather than a literal, any '%' the attacker lands inside it is
     interpreted as a placeholder specifier, which shifts or consumes arguments. This is the
     CVE-2022-21661 family (WP_Tax_Query). Known call sites to audit end to end:
       wp-includes/class-wp-meta-query.php:679,697,703,708,721,745,756,762,771
       wp-includes/post.php:3610  (prepare( \$query, ...\$args ))
       wp-includes/post.php:5771,5790,5805,5827,5835,5883  (\$check_sql built above)
       wp-admin/includes/post.php:910
     For each: trace backward to find who controls the pieces of the format string, and whether
     a '%' survives to reach prepare(). Note prepare() in modern core escapes '%' it generated
     itself - read wpdb::prepare in wp-includes/class-wpdb.php and establish EXACTLY what its
     current placeholder scanner accepts before claiming a bypass.

  b. IDENTIFIER INJECTION - table, column, ORDER BY, GROUP BY. These cannot be passed as %s;
     core added the %i placeholder in 6.2 but most call sites predate it. Hunt every place a
     COLUMN NAME is derived from a query var: WP_Query 'orderby'/'fields'/'search_columns',
     WP_User_Query 'orderby'/'search_columns'/'who', WP_Comment_Query 'orderby'/'fields',
     WP_Term_Query 'orderby'/'fields', WP_Date_Query::validate_column(),
     WP_Meta_Query 'key'/'type'/'compare' and its CAST(... AS <type>) construction, and
     get_terms()/get_posts() 'orderby'. sanitize_sql_orderby() is the guard - read it, then
     find the paths that never call it.

  c. ARRAY-SHAPED CLAUSE INJECTION. meta_query / date_query / tax_query accept NESTED ARRAYS.
     Ask for each builder: which array keys reach SQL as structure rather than as a value, and
     can a REST argument, a query var, a block attribute or a shortcode attribute supply a
     nested array at all? Reachability is the hard half here, not the sink. An unreachable
     builder bug is a note, not a finding.

  d. SECOND-ORDER. A value stored safely, then read back and concatenated into a query built
     later. Post meta, user meta, term meta, options, transients, widget instances.

  e. CHARSET / TRUNCATION CONFUSION. wpdb::strip_invalid_text(), ::_real_escape(),
     ::check_safe_collation() and the utf8mb4 handling can alter a string AFTER escaping.
     Look for a length or charset path that re-writes an already-escaped value.

  f. THE DEVELOPERS' OWN MARKERS. grep the tree for
       phpcs:ignore WordPress.DB.PreparedSQL
     Every one of those is a place a human decided the linter was wrong. Read each one and
     decide whether they were right.

  REACHABILITY IS THE GATE, NOT THE SINK. For every candidate, name the concrete request that
  reaches it and the role required: an unauthenticated GET, a REST argument, an admin-ajax
  action, a block attribute, a shortcode. If the only caller is admin-only schema or upgrade
  code, it is not a finding - say so and move on. A pre-auth or subscriber-reachable SQLi is
  the objective; an admin-only one is not interesting, because admin already owns the site.

  PROVING IT. You have a live MySQL 9.7 behind the lab. Prove the injection with a
  time-based or boolean differential against the real server, and show the generated SQL -
    (cd targets/wordpress-develop && docker compose logs --tail=200 php)
  plus \$wpdb->last_query via a wp-cli eval are your two windows onto the query that actually
  ran. D: escalate a confirmed SQLi toward reading wp_users.user_pass or a session token in
  wp_usermeta, which is the realistic path to administrator and therefore to RCE. Do not claim
  INTO OUTFILE without testing it - check the server's secure_file_priv first.

------------------------------------------------------------------------------
(2) XS-LEAKS AND CROSS-SITE ORACLES
------------------------------------------------------------------------------
Two sub-lanes. Do them in this order, because the first needs no victim and is therefore worth
strictly more.

  LANE 1 - SERVER-SIDE PRE-ACL ORACLES (no browser, no victim, highest value).
  A response that is correctly filtered in its BODY but leaks through a COUNT, a HEADER, a
  status code, a redirect target or a timing difference. One instance of exactly this shape is
  already confirmed on this target (REST comments X-WP-Total counted unfiltered rows). The same
  shape exists unaudited on EIGHT other controllers - posts, users, terms, search, revisions,
  global-styles-revisions, abilities-list, abilities-categories. The exact line numbers are in
  workspace/hints/track-b-xsleaks.md section 1. Test every one. For each ask:
    - is the count taken BEFORE the per-item permission filter?
    - is there a search/slug/include/meta parameter that turns an existence oracle into a
      CONTENT oracle (LIKE %term% lets you extend a prefix one character at a time)?
    - is the SCOPED form of the same query correctly refused while the unscoped form is not?
      That contrast is what proves it is a gate bypass rather than intended behaviour.

  LANE 2 - BROWSER-SIDE XS-LEAKS (needs a victim visiting an attacker page).
  The preconditions are already measured and written down in the hints file - no SameSite on
  any auth cookie, no COOP/COEP/CORP anywhere, X-Frame-Options only on wp-login and wp-admin,
  nothing on the front end or on admin-ajax. Build on those. The shapes worth hunting:
  status-code differentials on REST object routes, redirect-count differentials through
  redirect_canonical, size/timing differentials on ?s= search and the archives, frame counting
  via window.open on pages whose embed count depends on private content, the password-protected
  post form-versus-content differential, the GET-reachable admin-ajax search actions
  (ajax-tag-search, autocomplete-user, fetch-list), and oEmbed endpoints designed to be loaded
  cross-origin.

  A BROWSER XS-LEAK IS NOT A FINDING UNTIL IT RUNS IN A BROWSER. Use browser_probe.py. State in
  the finding which browser and which DEFAULT settings it assumes - Chrome Lax-by-default allows
  only top-level GET navigation, Firefox default allows subresource loads too, and a leak that
  needs non-default settings is not a finding. State the bits per request and the total request
  count honestly.

  THE DISQUALIFYING TEST, apply it to every XS-Leak candidate before writing it up: does this
  reveal anything the attacker could not already obtain through a channel WordPress documents as
  accepted? User and username enumeration, public post listings, the absence of login rate
  limiting and version disclosure are all ACCEPTED on this target. An oracle over PUBLIC data is
  not a vulnerability. The finding has to turn on PRIVATE state - another user's draft, private
  or password-protected content, an unapproved comment, a capability the viewer does not hold.
  Use the seeded markers so the proof is unambiguous: post 6 alice draft, post 7 alice private,
  post 9 bob draft, post 10 dave password-protected.
===============================================================================

THE LIVE LAB
  http://wsl.evm.pics:31655 serves targets/wordpress-develop/src DIRECTLY (docker bind mount
  ./:/var/www, nginx docroot /var/www/src). The code you read IS the code that runs - no build
  step sits between them, so every static claim is immediately testable.
  Stack: nginx:alpine -> wordpressdevelop/php:8.3-fpm -> mysql 9.7, all on the wpdevnet bridge.
  Config: WP_DEBUG=false, WP_DEBUG_DISPLAY=false, WP_ENVIRONMENT_TYPE='production',
  WP_DEVELOPMENT_MODE='', SCRIPT_DEBUG=true, single site (not multisite), permalinks
  /%year%/%monthnum%/%postname%/, users_can_register=1 (default_role=subscriber), only core
  themes/plugins (twentytwentyfive active, hello.php inactive). Treat it as a stock production
  single-site install: no third-party plugin or theme is in scope, every finding must be a CORE
  finding.
  Seeded objects for access-control work: post 5 alice publish, 6 alice draft
  (ALICE_SECRET_MARKER_7741), 7 alice private (ALICE_PRIVATE_MARKER_9920), 8 bob publish,
  9 bob draft (BOB_SECRET_MARKER_3310), 10 dave publish password-protected 'hunter2'
  (PROTECTED_MARKER_5512), comment 2 on post 1. Reading another identity's marker out of a
  response is a clean, unambiguous IDOR proof.
  Logging in: POST /wp-login.php with log=, pwd=, wp-submit=Log+In, testcookie=1 and a cookie
  jar; success is a 302 to /wp-admin/. For the REST API, cookie auth alone is NOT enough -
  WordPress requires the nonce too: pull it from the wp-admin HTML (wpApiSettings.nonce /
  wp.apiFetch nonce middleware) and send it as X-WP-Nonce. Application Passwords are
  deliberately unavailable here because the site is plain HTTP with WP_ENVIRONMENT_TYPE
  production - that is WordPress behaving as documented, not a bug and not a blocker.
  Inspecting state to PROVE impact is allowed and encouraged:
    (cd targets/wordpress-develop && npm --silent run env:cli -- <wp-cli args> --path=/var/www/src)
    (cd targets/wordpress-develop && docker compose logs --tail=200 php)
  NEVER edit a file under targets/. The live site is the same tree, so a stray edit silently
  changes the code under assessment. 'git -C targets/wordpress-develop status --porcelain -- src'
  must stay EMPTY (baseline: workspace/_target_baseline.txt); check it after any write-primitive
  PoC. A file-write proof must create a NEW uniquely-named marker file, never overwrite an
  existing core file.

WHERE WORDPRESS DRAWS ITS SECURITY BOUNDARIES - get this right before you call anything a bug.
  Allowed by design (C must close these as not_product_vulnerability unless the finding shows a
  lower-privileged actor crossing the line):
    - An administrator (single site) executing arbitrary PHP: plugin/theme file editor, plugin or
      theme upload, core updates. Admin -> RCE is the documented design, not a vulnerability.
    - unfiltered_html: administrators and editors on single site may post arbitrary HTML and
      JavaScript. Stored XSS BY an editor or admin on this single-site install is by design.
      Stored XSS by a CONTRIBUTOR or AUTHOR, who do not hold unfiltered_html, is a real bug.
    - User/username enumeration (author archives, /wp-json/wp/v2/users, oEmbed, login error
      differences) and the absence of built-in login rate limiting - both long-standing,
      documented, accepted.
    - XML-RPC pingback behavior (outbound fetch, amplification) - known and accepted.
    - Version disclosure, readme.html, directory listing, file permissions, server config.
  Real vulnerabilities, in descending value:
    T1 PRE-AUTH (no session at all): RCE, PHP object injection, SQL injection, authentication
       bypass, arbitrary file write/read, SSRF with a reachable sink, stored XSS.
    T2 LOW-PRIVILEGE ESCALATION: subscriber/contributor/author/editor reaching code execution,
       another user's private data, or a capability they do not hold. Contributor -> stored XSS
       (a kses bypass) and author -> arbitrary file write are the classic high-value WordPress
       bugs.
    T3 Cross-user IDOR, missing-nonce CSRF on state-changing actions, capability checks that are
       present but wrong (edit_post vs edit_others_posts vs publish_posts).
  Say explicitly, for every finding: which boundary it crosses and from which starting position
  (unauthenticated / subscriber / contributor / author / editor).

WHERE TO HUNT - WordPress's actual high-risk machinery.
  Pre-auth entry points, all of them front doors: src/wp-login.php (login, password reset,
  registration), src/wp-comments-post.php, src/wp-signup.php, src/wp-activate.php,
  src/wp-trackback.php, src/wp-cron.php, src/wp-mail.php, src/xmlrpc.php, src/wp-links-opml.php,
  /wp-json/* with permission_callback __return_true, admin-ajax.php wp_ajax_nopriv_* actions,
  admin-post.php nopriv actions, and the rewrite/query-var path (WP::parse_request,
  WP_Query::get_posts) reachable from any public URL.
  Injection and data flow (Track A):
    - SQL: every \$wpdb->query/get_results/get_var/get_row call where a value is interpolated
      instead of passed through prepare(); prepare() misuse (%i identifier placeholder added in
      6.2, '%s' already quoted in the format string, LIKE with esc_like, IN (...) lists built by
      implode, esc_sql on arrays); WP_Query orderby/meta_key/meta_query/date_query/tax_query,
      WP_Meta_Query::get_sql, WP_Date_Query, WP_Tax_Query, WP_User_Query, get_terms orderby,
      and REST 'orderby'/'order'/'search_columns' arguments that reach those builders.
    - PHP object injection: maybe_unserialize / unserialize on anything attacker-influenced -
      post meta, user meta, term meta, comment meta, options, transients, widget instances,
      _wp_attachment_metadata, _wp_page_template, oEmbed caches, theme mods, imported WXR.
      Then look for a POP chain in core itself (__destruct/__wakeup/__toString reaching
      file or exec operations).
    - File write and traversal: wp-admin/includes/file.php (wp_handle_upload, wp_handle_sideload,
      download_url, unzip_file, _unzip_file_ziparchive, _unzip_file_pclzip, copy_dir, wp_tempnam,
      WP_Filesystem_Direct), wp_check_filetype_and_ext, wp_unique_filename, sanitize_file_name,
      _wp_relative_upload_path, wp_normalize_path, plugin/theme install paths. Zip-slip and
      double-extension handling are the recurring themes.
    - SSRF: wp_remote_get/post (NO private-IP filter) vs wp_safe_remote_* (filtered by
      wp_http_validate_url); WP_Http::request redirect following in Requests; oEmbed discovery
      (WP_oEmbed::discover, get_oembed_response_data), SimplePie feed fetch, download_url,
      wp_remote_fopen, the HTTP API proxy constants, and anything in ai-client/php-ai-client that
      dials an endpoint derived from configuration or content. Bypass angles: DNS rebinding,
      IPv6 and IPv4-mapped forms, decimal/octal IPs, redirects to a private target,
      0.0.0.0, and userinfo@ tricks against wp_http_validate_url / wp_parse_url.
    - XSS and sanitizer escapes: wp_kses / wp_kses_hook / wp_kses_split / wp_kses_attr /
      safecss_filter_attr / wp_kses_bad_protocol - any input that reaches output while skipping
      esc_html/esc_attr/esc_url/wp_json_encode; block comment delimiters and attribute JSON
      (parse_blocks, serialize_block, WP_Block_Parser) where a crafted attribute survives kses;
      the HTML API (WP_HTML_Tag_Processor, WP_HTML_Processor, WP_HTML_Decoder) where a parsing
      differential with the browser lets markup through; and the Interactivity API
      (wp_interactivity_process_directives, data-wp-* directives, wp_interactivity_state JSON).
    - XXE and parser bugs: SimplePie, IXR/XML-RPC, wp_read_video_metadata and ID3, WXR import.
    - Command execution: any proc_open/exec/shell_exec/popen/system/passthru reachable with
      attacker-controlled arguments (image editors, ImageMagick paths).
  Logic and access control (Track B):
    - The capability engine itself: map_meta_cap, WP_User::has_cap, user_can, current_user_can,
      get_role, WP_Roles, and every caller that checks a PRIMITIVE cap where a META cap was
      required (edit_posts vs edit_post, edit_users vs edit_user, manage_options).
    - REST controllers under src/wp-includes/rest-api/endpoints: each *_permissions_check is a
      gate - compare it against what the handler then does, and look for object ownership never
      being checked, context=edit leaking fields, _fields/_embed bypassing a check, batch
      requests (/wp/v2/batch/v1), and meta exposure via register_meta auth_callback /
      is_protected_meta.
    - Nonce and referer: wp_verify_nonce (note it returns 2 for a 12-24h old nonce and is tied to
      user 0 when logged out), check_admin_referer, check_ajax_referer, and admin-ajax/admin-post
      actions that change state without either.
    - Authentication internals: wp_validate_auth_cookie and wp_generate_auth_cookie (hash
      construction, expiration handling, session tokens in WP_Session_Tokens), wp_hash,
      check_password_reset_key and get_password_reset_key, wp_signon, application passwords
      (WP_Application_Passwords), determine_current_user and rest_cookie_check_errors,
      wp_validate_redirect / wp_safe_redirect allow-list, and the login redirect_to handling.
    - Ownership: post/attachment/comment/user/term objects fetched by id and acted on without an
      ownership or status check - drafts, private posts, password-protected posts, revisions
      (wp_get_post_revision), autosaves, and media attached to someone else's post.
    - Newest and least-reviewed surface, prioritize it: src/wp-includes/abilities-api,
      src/wp-includes/ai-client, src/wp-includes/php-ai-client, src/wp-includes/block-bindings,
      src/wp-includes/interactivity-api, src/wp-includes/html-api. New code in a 20-year-old
      codebase is where the undiscovered bugs actually are.

CODE MODEL - read this before querying it.
  - workspace/CODE_MODEL.json is GRAPH-ONLY: 4085 analyzable files exceeded the dataflow
    threshold, so it carries symbols, entry points and a global index but no resolved sinks or
    paths. Use it as a directory, not as a taint map.
  - Full per-module models (dataflow + sinks + guards + proof ledger) are PRE-BUILT in
    workspace/cm/<name>.json. src-all covers the entire product tree (2512 files, full mode) and
    is the one to start from; the rest are focused views: core-includes, admin, admin-includes,
    rest-api, blocks, block-supports, block-bindings, block-patterns, html-api,
    interactivity-api, abilities-api, ai-client, php-ai-client, customize, widgets, sitemaps,
    style-engine, requests-http, simplepie, ixr-xmlrpc, phpmailer, id3, pomo, text-diff,
    theme-tt5, js-core, tools. Query them:
      python3 .agents/skills/source-model/scripts/callgraph.py --model workspace/cm/<n>.json --sinks
      python3 .agents/skills/source-model/scripts/callgraph.py --model workspace/cm/<n>.json --trace <sink>
      python3 .agents/skills/source-model/scripts/proof_ledger.py --ledger workspace/cm/<n>.proof_ledger.json --next route
  - OpenGrep leads for Track A are pre-generated in workspace/hints/.
  - The extractor is a regex/AST approximation on PHP: WordPress dispatches through hooks
    (add_action/add_filter/do_action/apply_filters), variable functions, call_user_func and
    \$wpdb magic, so the graph misses most real edges. Treat a graph edge as a hint and resolve
    the real target by reading the code and by grepping the hook name. Never report a path the
    graph asserts but the source does not.

DISCLOSURE WORK (C only, and only on confirmed product vulnerabilities).
  targets/wordpress-develop is a FULL git clone with complete history and an origin remote, so
  the whole exact-match ladder is available locally and you are expected to run it:
    git -C targets/wordpress-develop log --all -S'<literal>' -- src
    git -C targets/wordpress-develop log --all -G'<pattern>' -- <path>
    git -C targets/wordpress-develop fetch origin && git -C targets/wordpress-develop \\
      diff HEAD origin/trunk -- <path>
  Then the vendor sources: WordPress Core Trac (core.trac.wordpress.org) is the primary issue
  tracker - search it, not only GitHub. Also WordPress/wordpress-develop issues and PRs,
  make.wordpress.org/core, the HackerOne WordPress program policy and its disclosed reports,
  wordpress.org/news security releases, and the WPScan / Patchstack / CVE databases. A matching
  Trac ticket, changeset, commit, PR or regression test means 'known', with or without a CVE."

exec ./start.sh -u "$URL" --accounts "$ACCOUNTS" "$TARGET"
