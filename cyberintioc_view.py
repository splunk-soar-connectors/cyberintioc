import json
from django.http import HttpResponse
from django.template import loader
import phantom.app as phantom
from cyberintioc_connector import CyberintIocConnector
from cyberintioc_consts import IOC_FEED_DAILY_ENDPOINT
from datetime import datetime, timezone


def _render_enrichment_view(
    request, connector, handler, param, template_name, indicator_type, indicator_value
):
    action_result = connector.add_action_result(
        phantom.action_result.ActionResult(dict(param))
    )
    result = handler(param)
    if phantom.is_fail(result):
        return HttpResponse(
            f"Failed to enrich {indicator_type}: {action_result.get_message()}",
            status=500,
        )

    template = loader.get_template(template_name)
    context = {
        "data": action_result.get_data(),
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
    }
    return HttpResponse(template.render(context, request))


def enrich_sha256_view(request, **kwargs):
    connector = CyberintIocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()
    hash_value = request.GET.get("hash")
    param = {"Hash": hash_value}
    return _render_enrichment_view(
        request,
        connector,
        connector._handle_enrich_sha256,
        param,
        "enrich_sha256_view.html",
        "SHA256",
        hash_value,
    )


def enrich_ipv4_view(request, **kwargs):
    connector = CyberintIocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()
    ip_value = request.GET.get("ip")
    param = {"IP": ip_value}
    return _render_enrichment_view(
        request,
        connector,
        connector._handle_enrich_ipv4,
        param,
        "enrich_ipv4_view.html",
        "IPv4",
        ip_value,
    )


def enrich_url_view(request, **kwargs):
    connector = CyberintIocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()
    url_value = request.GET.get("url")
    param = {"URL": url_value}
    return _render_enrichment_view(
        request,
        connector,
        connector._handle_enrich_url,
        param,
        "enrich_url_view.html",
        "URL",
        url_value,
    )


def enrich_domain_view(request, **kwargs):
    connector = CyberintIocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()
    domain_value = request.GET.get("domain")
    param = {"Domain": domain_value}
    return _render_enrichment_view(
        request,
        connector,
        connector._handle_enrich_domain,
        param,
        "enrich_domain_view.html",
        "Domain",
        domain_value,
    )


def ioc_view(request, **kwargs):
    """
    This view function will be called by Splunk SOAR to display the daily IOC feed.
    """
    connector = CyberintIocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()

    action_result = connector.add_action_result(
        phantom.action_result.ActionResult(dict())
    )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    offset = 0
    limit = 100
    all_iocs = []

    while True:
        ioc_args = f"?limit={limit}&offset={offset}&format=json"
        ret_val, iocs = connector._make_rest_call(
            f"{IOC_FEED_DAILY_ENDPOINT}/{today}{ioc_args}", action_result
        )
        if phantom.is_fail(ret_val) or not iocs:
            break
        all_iocs.extend(iocs)
        offset += limit

    template = loader.get_template("ioc_view.html")
    context = {
        "iocs": all_iocs,
        "date": today,
    }
    return HttpResponse(template.render(context, request))


def enrich_indicator_view(request, **kwargs):
    """
    This view function will be called by Splunk SOAR to enrich an indicator.
    This can act as a generic dispatcher if needed, but specific views are better.
    """
    connector = CyberintIocConnector()
    connector.handle_action = lambda x: x
    connector.initialize()

    indicator_type = request.GET.get("type")
    indicator_value = request.GET.get("value")

    if not indicator_type or not indicator_value:
        return HttpResponse("Missing indicator type or value.", status=400)

    param = {}
    handler = None
    template_name = ""

    if indicator_type == "sha256":
        param = {"Hash": indicator_value}
        handler = connector._handle_enrich_sha256
        template_name = "enrich_sha256_view.html"
    elif indicator_type == "ipv4":
        param = {"IP": indicator_value}
        handler = connector._handle_enrich_ipv4
        template_name = "enrich_ipv4_view.html"
    elif indicator_type == "url":
        param = {"URL": indicator_value}
        handler = connector._handle_enrich_url
        template_name = "enrich_url_view.html"
    elif indicator_type == "domain":
        param = {"Domain": indicator_value}
        handler = connector._handle_enrich_domain
        template_name = "enrich_domain_view.html"
    else:
        return HttpResponse(f"Unsupported indicator type: {indicator_type}", status=400)

    return _render_enrichment_view(
        request,
        connector,
        handler,
        param,
        template_name,
        indicator_type,
        indicator_value,
    )
