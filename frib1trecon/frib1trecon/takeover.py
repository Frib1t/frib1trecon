"""
Subdomain takeover: un subdominio con CNAME hacia un servicio de terceros
(GitHub Pages, Heroku, S3, Azure...) cuyo destino ya no existe. Quien registre
ese nombre en el proveedor puede servir contenido bajo el subdominio de la
empresa. Solo consulta DNS (CNAME y resolucion del destino), sin peticiones HTTP.
"""
import socket
from concurrent.futures import ThreadPoolExecutor

import dns.resolver

from . import http_client

PROVIDERS = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "azurewebsites.net": "Azure App Service", "cloudapp.net": "Azure", "trafficmanager.net": "Azure",
    "s3.amazonaws.com": "AWS S3", "s3-website": "AWS S3", "cloudfront.net": "AWS CloudFront",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk", "fastly.net": "Fastly", "netlify.app": "Netlify",
    "netlify.com": "Netlify", "pantheonsite.io": "Pantheon", "surge.sh": "Surge", "bitbucket.io": "Bitbucket",
    "wordpress.com": "WordPress.com", "zendesk.com": "Zendesk", "readme.io": "ReadMe",
    "statuspage.io": "Statuspage", "ghost.io": "Ghost", "helpjuicer.com": "HelpJuice",
    "unbouncepages.com": "Unbounce", "tumblr.com": "Tumblr", "feedpress.me": "FeedPress",
    "uservoice.com": "UserVoice", "cargocollective.com": "Cargo", "shopify.com": "Shopify",
}

FINGERPRINTS = {
    "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html"],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app"],
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Azure App Service": ["404 Web Site not found", "Microsoft Azure App Service - Welcome"],
    "AWS CloudFront": ["Bad request. ERROR: The request could not be satisfied", "The request could not be satisfied"],
    "Fastly": ["Fastly error: unknown domain"],
    "Netlify": ["Not Found - Request ID", "page not found"],
    "Pantheon": ["404 error unknown site", "The gods are wise"],
    "Surge": ["project not found"],
    "Bitbucket": ["Repository not found"],
    "WordPress.com": ["Do you want to register"],
    "Zendesk": ["Help Center Closed", "this help center no longer exists"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Statuspage": ["You are being redirected", "Status page not found"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist at this address"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Cargo": ["404 Not Found"],
    "UserVoice": ["This UserVoice subdomain is currently available"],
}

TIMEOUT = 8
WORKERS = 20


def _cname(name: str) -> str | None:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT
    try:
        answer = resolver.resolve(name, "CNAME")
        return str(answer[0].target).rstrip(".").lower()
    except Exception:
        return None


def _provider_of(target: str) -> str | None:
    return next((name for suffix, name in PROVIDERS.items() if target.endswith(suffix)), None)


def _reclaimable(sub: str, provider: str) -> bool:
    """El proveedor muestra su pagina de 'no reclamado' para este subdominio."""
    import requests
    marks = FINGERPRINTS.get(provider, [])
    for scheme in ("https", "http"):
        r = http_client.get(f"{scheme}://{sub}", timeout=TIMEOUT, allow_redirects=True)
        if r is None:
            continue
        body = r.text or ""
        if any(m.lower() in body.lower() for m in marks):
            return True
    return False


def check_takeover(subdomains: list[str]) -> list[dict]:
    """Subdominios con CNAME a un proveedor cuya pagina indica que el recurso ya no existe."""
    if not subdomains:
        return []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        cnames = list(ex.map(_cname, subdomains))
    pending = []
    for sub, target in zip(subdomains, cnames):
        provider = _provider_of(target) if target else None
        if provider:
            pending.append((sub, target, provider))
    if not pending:
        return []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        verdicts = list(ex.map(lambda t: _reclaimable(t[0], t[2]), pending))
    return [{"subdomain": sub, "cname": target, "provider": provider}
            for (sub, target, provider), ok in zip(pending, verdicts) if ok]
