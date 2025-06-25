# Proyek Akhir Arsitektur Jaringan Modern: 

Merancang sistem Integrasi IDS Suricata dan Ryu Controller dalam SDN untuk Deteksi dan Pemblokiran Serangan Denial of Service

# Topologi Sistem
<p align="center">
  <img src="https://github.com/user-attachments/assets/e93af4d5-e2cd-44b2-bd89-c743c9bbc719" alt="Tpologi Sistem"/>
</p>
<p align="center"><em>Figure 1: Topologi minimum SDN dengan implementasi Suricata dan Ryu Controller</em></p>

Topologi jaringan yang digunakan pada proyek ini merupakan simulasi arsitektur Software-Defined Networking (SDN) yang mengintegrasikan Suricata sebagai Intrusion Detection System (IDS) dan Ryu sebagai SDN controller, dengan tujuan untuk mendeteksi dan memblokir serangan jaringan seperti Denial of Service (DoS). Topologi SDN ini terdiri dari Suricata, Ryu Controller (ryu), Open vSwitch (sw1), host (h1), dan server (srv1). Topologi direalisasikan pada jaringan virtual yang diimplementasikan pada mininet. Perangkat h1  merepresentasikan host yang merupakan pengguna jaringan, sekaligus menjadi potensi sumber serangan. H1 terhubung ke switch (sw1), yang berfungsi sebagai titik pusat lalu lintas jaringan. Ryu Controller dan Suricata IDS ditempatkan pada 1 host fisik yang sama.

Switch sw1 dikonfigurasi untuk melakukan mirroring lalu lintas ke Suricata, sehingga IDS dapat menganalisis semua paket yang lewat secara real-time. Jika Suricata mendeteksi adanya aktivitas DoS, maka Suricata akan mendeteksi IP penyerang dan Ryu Controller akan memblokir IP penyerang selama beberapa waktu. Ryu kemudian merespons dengan menginstal aturan baru (flow rule) ke dalam switch untuk memblokir lalu lintas dari/ke IP penyerang selama durasi tertentu agar tidak dapat melanjutkan akses ke jaringan.

<br />

<p align="center">
  <img src="https://github.com/user-attachments/assets/c7e6290c-ce8d-42e2-b10c-65a7e6a5b7b6" alt="Topologi Mininet drawio"/>
</p>
<p align="center"><em>Figure 2:  Topologi interface jaringan SDN mininet</em></p>

Gambar tersebut merupakan topologi simulasi jaringan dalam mininet beserta dengan konfigurasi IP interface, subnet, dan routing. Dalam simulasi yang akan dijalankan H1 bertindak sebagai penyerang dan SRV1 bertindak sebagai taget penyerangan. Dalam simulasi penyerangan SURICATA akan mendeteksi serangan tersebut dan akan membuat alert sehingga Ryu Controller dapat memblokir IP penyerang. 


# Requierment system

Sebelum menjalankan sistem, pastikan sistem Anda memiliki prasyarat berikut:
- **Ubuntu (Versi 22.04 LTS)**
- **Mininet (Versi 2.3.1b4)**
- **Ryu Controller (Versi 4.34)**
- **Suricata (Versi 6.0.4)**
- **Python (Versi 3.9)**
- **hping3**


# Cara Menjalankan Simulasi 

1. **Unduh atau Clone Repositori:**

```bash
https://github.com/ryoaditarta/sdnwithsuricata.git
cd sdnwithsuricata
```
<br />

2. **Menjalankan Sistem:**
   - Pastikan anda sudah berada dalam direktori dan gunakan environment apabila diperlukan.
   - Jalankan perintah berikut dalam command prompt dan persiapkan 3 tab untuk menjalankan system. 
 
Pertama, jalankan Ryu Controller pada tab pertama dengan perintah:
```bash
sudo ryu-manager ryucontroller.py 
```

Selanjutnya, jalankan Mininet pada tab kedua dengan perintah:
```bash
sudo python3 sdnmininet.py 
```

Terakhir, jalankan IDS Suricata dengan  pada tab ketiga dengan perintah:
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i S1-eth3
```
<br />
  
3. **Prosedur Pengujian:**
   - Perintah untuk simulasi serangan dijalankan dalam tab mininet dengan menggunakan hping3.

Serangan SYN Flood:
```bash
hping3 -S -c 1000 -i u10000 10.0.0.2
```

Serangan ICMP Flood:
```bash
hping3 -1 -c 1000 -i u10000 10.0.0.2
```

Serangan ACK Flood:
```bash
hping3 -A -c 1000 -i u10000 10.0.0.2
```

   - Dalam simulasi mininet, penyerangan dilakukan oleh node H1 dan SRV1 sebagai target.
   - Apabila serangan berhasil terblokir, maka akan muncul pesan IP yang ter-blacklist pada tab Ryu Controller.
   - Deteksi serangan oleh Suricata dapat dilihat melalui log yang dihasilkan suricata pada file /var/log/suricata/fast.log.
   - Untuk memastikan lalu lintas dari/menuju IP telah terblokir, jalankan perintah ```bash ovs-ofctl dump-flows S1 ``` pada tab baru.
   - Setelah durasi blockir selesai, Ryu Controller akan memunculkan notifikasi mengenai pembukaan blokir pada IP.
   - Untuk memastikan aturan flow IP telah terlepas, jalankan kembali perintah ```bash ovs-ofctl dump-flows S1 ```.

---
