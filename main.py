# coding=utf-8
import tkinter

# def start_capture():

top = tkinter.Tk()
top.title("py_sniffer")
top.geometry("1024x600")
start_button = tkinter.Button(top, text="开始抓包")
end_button = tkinter.Button(top, text="结束抓包")
follow_stream_button = tkinter.Button(top, text="流追踪")
help_button = tkinter.Button(top, text="帮助")
start_button.place(relx=0.05, rely=0.05, relwidth=0.1, relheight=0.05)
end_button.place(relx=0.2, rely=0.05, relwidth=0.1, relheight=0.05)
follow_stream_button.place(relx=0.35, rely=0.05, relwidth=0.1, relheight=0.05)
help_button.place(relx=0.5, rely=0.05, relwidth=0.1, relheight=0.05)


NC_variable = tkinter.StringVar()
NC_variable.set("选择网卡，默认全部")
network_card_optmenu = tkinter.OptionMenu(top, NC_variable, "one", "two", "three")
network_card_optmenu.place(relx=0.65, rely=0.05, relwidth=0.2, relheight=0.05)

BPF_lable = tkinter.Label(top, text="输入BPF表达式:")
BPF_entry = tkinter.Entry(top, width=70)
BPF_lable.place(relx=0.05, rely=0.15, relheight=0.05)
BPF_entry.place(relx=0.15, rely=0.15, relheight=0.05)

top.mainloop()