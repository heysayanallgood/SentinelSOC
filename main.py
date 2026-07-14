from modules.banner import show_banner
from modules.menu import show_menu
from core.router import route

def main():

    show_banner()

    choice = show_menu()

    route(choice)

if __name__ == "__main__":
    main()
