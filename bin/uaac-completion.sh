#! /bin/bash

#--
# Cloud Foundry
# Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#++

GLOBAL_OPTS="--help --no-help -h --version --no-version -v --debug --no-debug -d --trace --no-trace -t --config"

_debug() {
	if [[ $UAAC_DEBUG -eq 1 ]] ; then
		echo "$@;"
	fi
}

_add_completion_options() {
	local current="${COMP_WORDS[${COMP_CWORD}]}"
	COMPREPLY=( "${COMPREPLY[@]}" $(compgen -W "$1" -- $current) )
}

_uaac() {
	local current="${COMP_WORDS[${COMP_CWORD}]}"
	local helper_input=()
	if [[ "$current" == "" ]] || [[ "$current" == " " ]] || [[ $current == -* ]] ; then
		helper_input=( ${COMP_WORDS[@]} )
	else
		helper_input=( ${COMP_WORDS[@]/$current/} )
	fi

	local parent_command="${COMP_WORDS[0]}"
	local uaac_opts=$(completion-helper "${parent_command}" "${helper_input[@]}")
	local opts=$uaac_opts
	if [[ $current == -* ]] ; then
		opts="${GLOBAL_OPTS} ${uaac_opts}"
	fi
	_add_completion_options "${opts}"

}

complete -F _uaac uaac
