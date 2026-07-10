"""Banner display module"""

from colorama import Fore, Style

BANNER = f"""
{Fore.RED}██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗
{Fore.RED}██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝
{Fore.RED}██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║
{Fore.RED}██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║
{Fore.RED}██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║
{Fore.RED}╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
{Style.RESET_ALL}
{Fore.CYAN}[*] Bug Bounty Hunting Automation Tool v2.0.0
{Fore.CYAN}[*] Target: whatnot.com
{Fore.CYAN}[*] Author: h4ckr
{Style.RESET_ALL}"""

def print_banner():
    print(BANNER)
