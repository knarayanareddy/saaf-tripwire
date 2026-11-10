# SAAF Tripwire red-team results

Run: `.venv/bin/python redteam/run.py` (regenerates every case dir and this file). TW-SEC1 counts as caught only at high/critical (info = passes `--fail-on high`).

| Rule | Evasions tried | Evaded | False positives found | Control fired |
|---|---|---|---|---|
| TW-SEC1 | 13 | 0 | 0/4 | 1/1 |
| TW-NET1 | 11 | 0 | 0/3 | 1/1 |
| TW-NET2 | 7 | 0 | 0/1 | 1/1 |
| TW-OUT1 | 13 | 0 | 0/4 | 1/1 |
| TW-LLM1 | 8 | 0 | 0/3 | 1/1 |
| TW-CI2 | 3 | 1 | 0/1 | 1/1 |
| TW-GATE1 | 7 | 0 | 0/2 | 1/1 |

## Per case

| Rule | Case | Verdict | Findings |
|---|---|---|---|
| TW-SEC1 | `ctl_env_anthropic` | control fired | critical .env:1 |
| TW-SEC1 | `evades_split_concat` | CAUGHT | critical llm.py:1 |
| TW-SEC1 | `evades_base64` | CAUGHT | critical cfg.py:2 |
| TW-SEC1 | `evades_stripe_live` | CAUGHT | critical billing.py:2 |
| TW-SEC1 | `evades_hf_token` | CAUGHT | critical embed.py:1 |
| TW-SEC1 | `evades_generic_key_py` | CAUGHT | high settings.py:2 |
| TW-SEC1 | `evades_compose_env` | CAUGHT | high docker-compose.yml:5 |
| TW-SEC1 | `evades_yaml_anchor` | CAUGHT | high config.yaml:2 |
| TW-SEC1 | `evades_export_sh` | CAUGHT | high start.sh:2 |
| TW-SEC1 | `evades_pem_triple_quoted` | CAUGHT | critical signer.py:1 |
| TW-SEC1 | `evades_long_minified_line` | CAUGHT | critical assets/index.js:1 |
| TW-SEC1 | `evades_utf16_env` | CAUGHT | critical .env:1 |
| TW-SEC1 | `evades_fixture_dir_mark` | CAUGHT | critical fixtures/client.py:2 |
| TW-SEC1 | `evades_db_url_password` | CAUGHT | high .env:1 |
| TW-SEC1 | `fp_supabase_anon_key` | ok (silent) |  |
| TW-SEC1 | `fp_auth_scopes` | ok (silent) |  |
| TW-SEC1 | `fp_keycloak_path` | ok (silent) |  |
| TW-SEC1 | `fp_sha_pinned_token_name` | ok (silent) |  |
| TW-NET1 | `ctl_flask_run` | control fired | medium app.py:5 |
| TW-NET1 | `evades_host_in_main_block` | CAUGHT | medium main.py:8 |
| TW-NET1 | `evades_uvicorn_config_server` | CAUGHT | medium main.py:4 |
| TW-NET1 | `evades_flask_application_positional` | CAUGHT | medium wsgi.py:3 |
| TW-NET1 | `evades_pydantic_settings` | CAUGHT | medium main.py:8 |
| TW-NET1 | `evades_gunicorn_conf` | CAUGHT | medium gunicorn.conf.py:1 |
| TW-NET1 | `evades_dockerfile_exec_form` | CAUGHT | medium Dockerfile:3 |
| TW-NET1 | `evades_js_host_const` | CAUGHT | medium server.js:5 |
| TW-NET1 | `evades_js_api_name` | CAUGHT | medium index.ts:4 |
| TW-NET1 | `evades_vite_host_flag` | CAUGHT | medium package.json:1 |
| TW-NET1 | `evades_auth_word_in_comment` | CAUGHT | medium app.py:5 |
| TW-NET1 | `evades_auth_on_one_route_only` | CAUGHT | medium main.py:10 |
| TW-NET1 | `fp_docker_published_localhost` | ok (silent) |  |
| TW-NET1 | `fp_express_custom_apikey_mw` | ok (silent) |  |
| TW-NET1 | `fp_flask_before_request_auth` | ok (silent) |  |
| TW-NET2 | `ctl_fastapi_star` | control fired | medium main.py:4 |
| TW-NET2 | `evades_origins_constant` | CAUGHT | medium main.py:5 |
| TW-NET2 | `evades_starlette_middleware_list` | CAUGHT | medium main.py:4 |
| TW-NET2 | `evades_flask_headers_add` | CAUGHT | medium app.py:5 |
| TW-NET2 | `evades_flask_reflect_origin_update` | CAUGHT | medium app.py:5 |
| TW-NET2 | `evades_js_setheader_no_cors_word` | CAUGHT | medium server.js:3 |
| TW-NET2 | `evades_cors_origin_callback` | CAUGHT | medium app.ts:4 |
| TW-NET2 | `evades_cors_credentials_only` | CAUGHT | medium app.js:3 |
| TW-NET2 | `fp_flask_cors_resources_star_key` | ok (silent) |  |
| TW-OUT1 | `ctl_fstring_td` | control fired | medium report.py:4 |
| TW-OUT1 | `evades_str_format` | CAUGHT | medium report.py:2 |
| TW-OUT1 | `evades_percent_format` | CAUGHT | medium report.py:2 |
| TW-OUT1 | `evades_function_param` | CAUGHT | medium page.py:2 |
| TW-OUT1 | `evades_method_call` | CAUGHT | medium report.py:2 |
| TW-OUT1 | `evades_untracked_tag_input` | CAUGHT | medium search.py:3 |
| TW-OUT1 | `evades_numeric_name_level` | CAUGHT | medium report.py:2 |
| TW-OUT1 | `evades_js_concat_innerhtml` | CAUGHT | medium ui.js:1 |
| TW-OUT1 | `evades_js_destructured` | CAUGHT | medium ui.js:1 |
| TW-OUT1 | `evades_js_description_matches_esc` | CAUGHT | medium ui.js:1 |
| TW-OUT1 | `evades_js_nullish` | CAUGHT | medium table.ts:1 |
| TW-OUT1 | `evades_react_dangerously` | CAUGHT | medium Post.tsx:2 |
| TW-OUT1 | `evades_vue_vhtml` | CAUGHT | medium Answer.vue:1 |
| TW-OUT1 | `evades_markup_wrap` | CAUGHT | medium views.py:3 |
| TW-OUT1 | `fp_log_line_with_tag` | ok (silent) |  |
| TW-OUT1 | `fp_jinja_prompt_env` | ok (silent) |  |
| TW-OUT1 | `fp_js_textcontent_template` | ok (silent) |  |
| TW-OUT1 | `fp_amount_numeric` | ok (silent) |  |
| TW-LLM1 | `ctl_fstring_document` | control fired | high agent.py:4 |
| TW-LLM1 | `evades_jira_summary` | CAUGHT | high triage.py:5 |
| TW-LLM1 | `evades_clean_token_in_name` | CAUGHT | high agent.py:5 |
| TW-LLM1 | `evades_langchain_dict` | CAUGHT | high chain.py:7 |
| TW-LLM1 | `evades_kwargs_unpack` | CAUGHT | high agent.py:4 |
| TW-LLM1 | `evades_wrapper_fn` | CAUGHT | high agent.py:4; high agent.py:6 |
| TW-LLM1 | `evades_raw_http` | CAUGHT | high agent.py:4 |
| TW-LLM1 | `evades_typescript` | CAUGHT | high agent.ts:5 |
| TW-LLM1 | `evades_html_escape_counts_as_fence` | CAUGHT | high agent.py:4 |
| TW-LLM1 | `fp_inline_nonce_fence` | ok (silent) |  |
| TW-LLM1 | `fp_exit_code_param` | ok (silent) |  |
| TW-LLM1 | `fp_own_rubric_file` | ok (silent) |  |
| TW-CI2 | `ctl_title_in_run` | control fired | high .github/workflows/w.yml:7 |
| TW-CI2 | `evades_github_script` | CAUGHT | high .github/workflows/w.yml:10 |
| TW-CI2 | `evades_tojson_event` | EVADED |  |
| TW-CI2 | `evades_review_body_anchor` | CAUGHT | high .github/workflows/w.yml:9; high .github/workflows/w.yml:9 |
| TW-CI2 | `fp_body_via_env` | ok (silent) |  |
| TW-GATE1 | `ctl_get_default_pass` | control fired | medium gate.py:2 |
| TW-GATE1 | `evades_except_log_continue` | CAUGHT | high gate.py:8 |
| TW-GATE1 | `evades_dict_lookup_default` | CAUGHT | medium gate.py:3 |
| TW-GATE1 | `evades_or_default` | CAUGHT | medium gate.py:2 |
| TW-GATE1 | `evades_getattr_default` | CAUGHT | medium gate.py:2 |
| TW-GATE1 | `evades_match_wildcard` | CAUGHT | high gate.py:6 |
| TW-GATE1 | `evades_nan_via_diff_var` | CAUGHT | high match.py:3 |
| TW-GATE1 | `evades_substr_lower` | CAUGHT | high cov.py:2 |
| TW-GATE1 | `fp_csv_import_skips_invalid` | ok (silent) |  |
| TW-GATE1 | `fp_pandas_isna_guard` | ok (silent) |  |
