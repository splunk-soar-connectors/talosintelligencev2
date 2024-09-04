# File: zscaler_view.py
#
# Copyright (c) 2017-2023 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
def get_ctx_result(result):

    ctx_result = {}

    ctx_result['summary'] = result.get_summary()
    ctx_result['param'] = result.get_param()
    ctx_result['status'] = result.get_status()

    message = result.get_message()

    # if status is failure then add the message
    if not ctx_result['status']:
        ctx_result['message'] = message

    data = result.get_data()

    if not data:
        return ctx_result

    # flattening the dictionary so it's easier to display
    for i in range(len(data)):
        res = data[i]
        if "datasets" in res:
            datasets = res.pop("datasets")
            for datatype in datasets:
                for k, v in datasets[datatype].items():
                    combined_key = datatype + "_" + k
                    res[combined_key] = v
            data[i] = res

    ctx_result['data'] = data

    return ctx_result


def display_view(provides, all_app_runs, context):

    context["results"] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:

            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return "tallos_domain_prevalence.html"
