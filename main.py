from modules.banner import show_banner
from modules.menu import show_menu
from core.router import route

def main():

    while True:

        show_banner()

        choice = show_menu()

        if choice == "0":
            route(choice)
            break

        route(choice)

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
