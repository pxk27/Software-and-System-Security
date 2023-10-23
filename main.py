# coding=utf-8
import tkinter
from tkinter import *
from tkinter import messagebox
from scapy.all import *
from scapy.all import IP,TCP
import psutil

def follow_stream():
    def show_follow_packet():
        index = listbox_stream.curselection()[0]
        index_in_packet = follow_index[index]
        follow_info_window = tkinter.Tk()
        follow_info_window.title("流跟踪包的详细信息")
        follow_info_window.geometry("500x500")
        follow_info_text = tkinter.Text(follow_info_window)
        follow_info_text.insert(INSERT, package[index_in_packet].show(True, True))
        follow_info_text.place(relheight=1, relwidth=1)
        follow_info_text.config(state=tkinter.DISABLED)
        follow_info_window.mainloop()

    stream_window = tkinter.Tk()
    stream_window.title("流跟踪")
    stream_window.geometry("500x500")
    xScrollbar = tkinter.Scrollbar(stream_window, orient="horizontal")
    xScrollbar.pack(side="bottom", fill="x")
    yScrollbar = tkinter.Scrollbar(stream_window)
    yScrollbar.pack(side="right", fill="y")
    listbox_stream = tkinter.Listbox(stream_window, width=150, height=25, yscrollcommand=yScrollbar.set, xscrollcommand=xScrollbar.set)
    listbox_stream.bind("<Double-Button-1>", show_follow_packet)
    listbox_stream.pack(side="bottom", fill="both")
    xScrollbar.config(command=listbox_stream.xview)
    yScrollbar.config(command=listbox_stream.yview)
    
    follow_index = []
    index = listbox.curselection()[0]
    select_packet = package[index]
    if IP in select_packet:
        select_src = select_packet[IP].src
        select_dst = select_packet[IP].dst
    else:
        select_src = select_packet.src
        select_dst = select_packet.dst

    for index, item in enumerate(package):
        if IP in package:
            src = item[IP].src
            dst = item[IP].dst
        else:
            src = item.src
            dst = item.dst
        if select_src == src and select_dst == dst:
            if TCP in select_packet:
                if item[TCP].sport == select_packet[TCP].sport:
                    pass
        elif select_src == dst and select_dst == src:
            if TCP in select_packet:
                if item[TCP].sport == select_packet[TCP].dport:
                    pass
        else:
            continue
        follow_index.append(index)
        listbox_stream.insert("end", item.summary())
    stream_window.mainloop()

def show_info_packet(whatever):
    info_window = tkinter.Tk()
    info_window.title("包的详细信息")
    info_window.geometry("500x500")
    # xScrollbar = tkinter.Scrollbar(top, orient="horizontal")
    # xScrollbar.pack(side="bottom", fill="x")
    # yScrollbar = tkinter.Scrollbar(top)
    # yScrollbar.pack(side="right", fill="y")
    index = listbox.curselection()[0]
    info_text = tkinter.Text(info_window)
    info_text.insert(INSERT, package[index].show(True, True))
    info_text.place(relheight=1, relwidth=1)
    info_text.config(state=tkinter.DISABLED)
    info_window.mainloop()

def get_network_card():
    NC_name=[]
    interface_list = psutil.net_if_addrs()
    for index, (interface, addresses) in enumerate(interface_list.items(), 1):
        NC_name.append(interface)
    # print(NC_name)
    return NC_name

def start_capture():
    global sniffer
    if BPF_entry.get() != "":
        # print("not emptry")
        try:
            arch.common.compile_filter(BPF_entry.get())
        except:
            messagebox.showerror(title="error", message="BPF表达式错误！")
            return
    try:
        NC_var = NC_variable.get()
        if NC_var == "选择网卡，默认全部":
            sniffer = AsyncSniffer(store=True, filter=BPF_entry.get())
        else:
            sniffer = AsyncSniffer(iface=NC_var, store=True, filter=BPF_entry.get())
        start_button = tkinter.Button(top, text="正在抓包", command=start_capture).place(relx=0.05, rely=0.05, relwidth=0.1, relheight=0.05)
        sniffer.start()
        listbox.delete(0, END)
    except:
        messagebox.showerror(title="error", message="抓包失败！")

def end_capture():
    try:
        global package
        package=sniffer.stop()
        tkinter.Button(top, text="开始抓包", command=start_capture).place(relx=0.05, rely=0.05, relwidth=0.1, relheight=0.05)
        for item in package:
            listbox.insert("end", item.summary())
    except:
        messagebox.showerror(title="error", message="停止失败！")




top = tkinter.Tk()
top.title("py_sniffer")
top.geometry("1024x600")
start_button = tkinter.Button(top, text="开始抓包", command=start_capture)
end_button = tkinter.Button(top, text="结束抓包", command=end_capture)
follow_stream_button = tkinter.Button(top, text="流追踪", command=follow_stream)
help_button = tkinter.Button(top, text="帮助")
start_button.place(relx=0.05, rely=0.05, relwidth=0.1, relheight=0.05)
end_button.place(relx=0.2, rely=0.05, relwidth=0.1, relheight=0.05)
follow_stream_button.place(relx=0.35, rely=0.05, relwidth=0.1, relheight=0.05)
help_button.place(relx=0.5, rely=0.05, relwidth=0.1, relheight=0.05)

NC_name=get_network_card()
NC_variable = tkinter.StringVar()
NC_variable.set("选择网卡，默认全部")
network_card_optmenu = tkinter.OptionMenu(top, NC_variable, *NC_name)
network_card_optmenu.place(relx=0.65, rely=0.05, relwidth=0.2, relheight=0.05)

BPF_lable = tkinter.Label(top, text="输入BPF表达式:")
BPF_entry = tkinter.Entry(top, width=70)
BPF_lable.place(relx=0.05, rely=0.15, relheight=0.05)
BPF_entry.place(relx=0.15, rely=0.15, relheight=0.05)

xScrollbar = tkinter.Scrollbar(top, orient="horizontal")
xScrollbar.pack(side="bottom", fill="x")
yScrollbar = tkinter.Scrollbar(top)
yScrollbar.pack(side="right", fill="y")

listbox = tkinter.Listbox(top, width=150, height=25, yscrollcommand=yScrollbar.set, xscrollcommand=xScrollbar.set)
listbox.bind("<Double-Button-1>", show_info_packet)
listbox.pack(side="bottom", fill="both")

xScrollbar.config(command=listbox.xview)
yScrollbar.config(command=listbox.yview)

top.mainloop()