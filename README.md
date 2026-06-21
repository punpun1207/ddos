SDN DDoS Detect and Block (7/6/26)

Hệ thống mô phỏng, phát hiện và tự động chặn tấn công mạng DDoS (ICMP, UDP, TCP SYN) dựa trên kiến trúc SDN và DNN.  


1. Chức năng đang phát triển và hoàn thiện:  

a. Mininet: topology.py sinh traffic tùy chọn, generate_ddos_traffic1 sinh traffic thiết lập sẵn  
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/cb79e88a-d7bb-478e-9f04-4e8219673450" />

b. Deep Learning: Tích hợp mô hình DNN phân tích lưu lượng và phân loại DDOS từ các Switch ảo theo thời gian thực.  
c. Ryu Controller:  
<img width="1852" height="479" alt="image" src="https://github.com/user-attachments/assets/4edc6f03-b66a-4f05-9a31-2e1d052266d9" />

d. Dashboard (đang phát triển thêm):  
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-23-04" src="https://github.com/user-attachments/assets/11c6a058-275b-41f9-8760-06734cd96666" />
  <img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e24e0e1c-923f-462e-b18f-755ec345ce3f" />

2. Demo   
a. generate_ddos_traffic1  
Ryu controller:  
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-27-24" src="https://github.com/user-attachments/assets/13f5ca31-28bf-4cf8-bbc2-37b3e4248567" />


ICMP Flood:  
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-21-28" src="https://github.com/user-attachments/assets/9881371b-925a-45f0-a8ec-2a829ae1caca" />
UDP Flood:
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-22-50" src="https://github.com/user-attachments/assets/cf9946dc-441d-4235-8464-9d30e20967cd" />

TCP-SYN Flood:
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-23-49" src="https://github.com/user-attachments/assets/e2642c9f-3c7b-42f7-83a1-fb57e75eefbd" />

TCP-ACK Flood:
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-24-57" src="https://github.com/user-attachments/assets/8a04c0d7-f886-4d6b-9672-1c5a7925ebae" />

b. Qua mininet topology:

Thử với "h2 hping3 -S --flood --rand-source 10.0.0.1 -p 80": TCP-SYNC flood thủ công  
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-35-11" src="https://github.com/user-attachments/assets/02b34052-5ac3-43f0-99f8-7df870a837d8" />
Ryu Cpntroller:  
<img width="1920" height="1080" alt="Screenshot From 2026-06-07 15-27-24" src="https://github.com/user-attachments/assets/5de7282f-b264-44b6-9c7b-af0e91704c48" />

4. Hướng dẫn chạy:

B1: Khởi động Ryu controller:<terminal 1>  
source ryu_env/bin/activate  
ryu-manager 1cl_strict_.py  / 1cl strict4

B2: Khởi dộng Wireshark và cấu hình mạng<terminal 2>  
1> wireshark : sudo wireshark  
2> sudo python3 topology.py hoặc tự động bằng generate_ddos_trafic1.py  
  
B3: Khởi động dashboard:<terminal 3>  
sudo python3 dashboard.py  
và vào địa chỉ http://localhost:8080/  


5. Lý thuyết:

https://www.overleaf.com/project/6a0db7758c56245d7aef99bf
