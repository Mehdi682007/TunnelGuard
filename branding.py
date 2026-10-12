"""Terminal branding with a compact fallback for narrow consoles."""
import shutil
import sys
from tunnelguard import VERSION

ART = '█▀▀▀▀▀▀▀▀▄  █▀▀▀▀▀▀▀▀▄                     █▀▀▀▀▀▀▀▀▀█ █▀▀█   █▀▀█ █▀▀▀▄  █▀▀█ █▀▀▀▄  █▀▀█  ▄▀▀▀▀▀▀▀▀█ █▀▀█              ▄▀▀▀▀▀▀▀▀█ █▀▀█   █▀▀█  ▄▀▀▀▀▀▀▀▄  █▀▀▀▀▀▀▀▀▄  █▀▀▀▀▀▀▀▀▄ \n█  ▄▄▄▄   █ █  ▄▄▄▄   █                    █▄▄▄██▄▄▄▄█ █  █   █  █ █    ▀▄█  █ █    ▀▄█  █ █  █▄▄▄▄▄▄█ █  █             █  █▄▄▄▄▄▄█ █  █   █  █ █   ▄▄▄   █ █  ▄▄▄▄   █ █  ▄▄▄▄   █\n█  █▄▄▄▀  █ █  █   █  █      █▀▀▀▀▀▀█         █  █     █  █   █  █ █  █▄  ▀  █ █  █▄  ▀  █ █  █▄▄▄▄▄   █  █             █  █ ▄▄▄▄▄▄ █  █   █  █ █  █   █  █ █  █▄▄▄▀  █ █  █   █  █\n▀        ▄  ▀  █   ▄  ▄      █▄▄▄▄▄▄█         ▀  █     ▀  ▀   ▄  ▄ ▀  █ ▀▄   ▄ ▀  █ ▀▄   ▄ ▀       █   ▀  ▀             ▀  ▀ █  ███ ▀  ▀   ▄  ▄ ▀  ▀▄▄▄█  ▄ ▀        ▄  ▀  █   ▄  ▄\n█  █▀▀▀▀▀   █  █   █  █                       █  █     █  █   █  █ █  █   █  █ █  █   █  █ █  █▀▀▀▀▀   █  █             █  █ ▀▀████ █  █   █  █ █         █ █  █▀▀▀▄  █ █  █   █  █\n█  █        █  ▀▀▀▀   █                       █  █     █   ▀▀▀   █ █  █   █  █ █  █   █  █ █  █▀▀▀▀▀▀█ █  █▀▀▀▀▀▀█      █  █▀▀▀▀███ █   ▀▀▀   █ █  █▀▀▀█  █ █  █   █  █ █  ▀▀▀▀   █\n█▄▄█        █▄▄▄▄▄▄▄▄▀                        █▄▄█      ▀▄▄▄▄▄▄▄▀  █▄▄█   █▄▄█ █▄▄█   █▄▄█  ▀▄▄▄▄▄▄▄▄█  ▀▄▄▄▄▄▄▄▄█       ▀▄▄▄▄▄▄▄▄█  ▀▄▄▄▄▄▄▄▀  █▄▄█   █▄▄█ █▄▄█   █▄▄█ █▄▄▄▄▄▄▄▄▀'
COMPACT = r"""
+------------------------------------------+
|          PD - TUNNEL GUARD                |
|        TWO SERVERS. MORE PATHS.           |
+------------------------------------------+
"""

def banner(full=False):
    width = shutil.get_terminal_size((80, 24)).columns
    art = ART if full or width >= max(map(len, ART.splitlines())) else COMPACT
    return f"{art}\n🚀 TunnelGuard v{VERSION} | Paired tunnel manager\n🔗 github.com/Mehdi682007/TunnelGuard\n"

def display(text):
    encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
    print(text.encode(encoding, errors='replace').decode(encoding))
