from kivy.core.text import LabelBase
from kivy.uix.screenmanager import ScreenManager
from kivymd.app import MDApp
from kivy.uix.button import Button
from kivymd.uix.menu import MDDropdownMenu
from kivymd.uix.list import OneLineListItem
from kivy.properties import ObjectProperty
from kivy.clock import Clock
from kivy.lang import Builder
import ip_util
from ip_util import data, control, greet, chunksize
from client import send_file, start_client, run_scan, devices


class Slope(MDApp):
    def build(self):
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.primary_palette = "BlueGray"
        screen_manager = ScreenManager()
        screen_manager.add_widget(Builder.load_file("homepage.kv"))
        screen_manager.add_widget(Builder.load_file("client.kv"))
        screen_manager.add_widget(Builder.load_file("server.kv"))
        return screen_manager

    def show_device_details(self):
        return f"Your Device Details : \nComputer Name : {hostname}\nIP Address : {ip}"

    show_devices_scanned = False

    def show_connect_button(self):
        self.show_devices_scanned = True
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.devices_button.opacity = 1
        client_screen.ids.devices_button.disabled = False

    def hide_connect_button(self):
        self.show_devices_scanned = False
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.devices_button.opacity = 0
        client_screen.ids.devices_button.disabled = True

    dropdown = ObjectProperty()

    def on_start(self):
        self.dropdown = MDDropdownMenu()
        for i in devices:
            self.dropdown.items.append(
                {
                    "viewclass": "OneLineListItem",
                    "text": f"Device {i}",
                    "callback": lambda x, text_item=f"Device {i}": self.option_callback(
                        text_item
                    ),
                }
            )

    selected_device = None

    def option_callback(self, text_item):
        self.selected_device = text_item.text
        print(f"Selected Device : {self.selected_device}")
        self.connected_device()

    def connected_device(self):
        if self.selected_device:
            print(f"Connected to {self.selected_device}")
        else:
            return print("No device selected")

    show_file_path = False

    def show_files_button(self):
        self.show_file_path = True
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.file_path.opacity = 1
        client_screen.ids.file_path.disabled = False
        client_screen.ids.send_file_path_button.opacity = 1
        client_screen.ids.send_file_path_button.disabled = False

    def hide_files_button(self):
        self.show_file_path = False
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.file_path.opacity = 0
        client_screen.ids.file_path.disabled = True
        client_screen.ids.file_path.text = ""
        client_screen.ids.send_file_path_button.opacity = 0
        client_screen.ids.send_file_path_button.disabled = True

    def get_file_path(self):
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        print(client_screen.ids.file_path.text)

    show_progress_bar = False

    def show_progress(self):
        self.show_progress_bar = True
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.progress_bar.opacity = 1
        client_screen.ids.file_path.disabled = False

    def hide_progress(self):
        self.show_progress_bar = False
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.progress_bar.value = 0
        client_screen.ids.progress_bar.opacity = 0
        client_screen.ids.file_path.disabled = True
        client_screen.ids.file_sent_label.opacity = 0

    def progress_bar(self):
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.progress_bar.value = 0
        Clock.schedule_interval(self.update_progress, 1)

    def update_progress(self, dt):
        screen_manager = self.root
        client_screen = screen_manager.get_screen("client")
        client_screen.ids.progress_bar.value += 10
        if client_screen.ids.progress_bar.value >= 100:
            Clock.unschedule(self.update_progress)
            client_screen.ids.file_sent_label.opacity = 1

    show_server_progress_bar = False

    def show_server_progress(self):
        self.show_server_progress_bar = True
        screen_manager = self.root
        server_screen = screen_manager.get_screen("server")
        server_screen.ids.progress_bar.opacity = 1

    def hide_server_progress(self):
        self.show_server_progress_bar = False
        screen_manager = self.root
        server_screen = screen_manager.get_screen("server")
        server_screen.ids.file_label.opacity = 0
        server_screen.ids.progress_bar.value = 0
        server_screen.ids.progress_bar.opacity = 0

    def server_progress_bar(self):
        screen_manager = self.root
        server_screen = screen_manager.get_screen("server")
        server_screen.ids.progress_bar.value = 0
        Clock.schedule_interval(self.server_update_progress, 1)

    def server_update_progress(self, dt):
        screen_manager = self.root
        server_screen = screen_manager.get_screen("server")
        server_screen.ids.progress_bar.value += 10
        if server_screen.ids.progress_bar.value >= 100:
            Clock.unschedule(self.update_progress)
            server_screen.ids.file_label.opacity = 1

    def scan_devices(self):
        run_scan(iprange)
        print(devices)


if __name__ == "__main__":
    ip_addr, hostname = ip_util.get_ip()
    ip = ip_util.choose_ip(ip_addr, hostname)
    iprange = ip_util.get_ip_range(ip)
    LabelBase.register(
        name="Raleway",
        fn_regular="../../assets/Raleway-Regular.ttf",
        fn_bold="../../assets/Raleway-Medium.ttf",
    )
    LabelBase.register(
        name="RalewayThin",
        fn_regular="../../assets/Raleway-Light.ttf",
        fn_bold="../../assets/Raleway-Regular.ttf",
    )
    Slope().run()

