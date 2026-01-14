# دليل استكشاف الأخطاء وإصلاحها - Analytical-Intelligence v1

> دليل عملي وسريع لحل المشاكل الشائعة باستخدام أوامر Docker.

---

## 1) خدمة المحلل غير قابلة للوصول / خطأ "Connection refused" في المستشعر

### الأعراض:
- خطأ في `flow-collector` أو `suricata-shipper`: لا يمكن POST إلى `http://<ANALYZER_HOST>:8000`
- رسالة "Connection refused" في السجلات
- عدم ظهور بيانات في لوحة التحكم

### الإصلاح:

**على خادم المحلل (Analyzer):**
```bash
# التحقق من حالة الحاويات
docker compose ps

# التحقق من صحة الخدمة
curl http://localhost:8000/api/v1/health

# إعادة تشغيل الخدمات إذا لزم الأمر
docker compose restart backend

# التحقق من أن المنفذ مفتوح
ss -tlnp | grep 8000
```

**على خادم المستشعر (Sensor):**
```bash
# التحقق من إعداد ANALYZER_HOST في ملف .env
cat .env | grep ANALYZER_HOST

# تحديث العنوان إذا تغير
nano .env
# ANALYZER_HOST=<IP_الصحيح>

# إعادة تشغيل المستشعرات
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

---

## 2) عدم تطابق مفتاح API (خطأ 401 Unauthorized)

### الأعراض:
- خطأ `401 Unauthorized` في سجلات المستشعر
- فشل `sample_sender` أو أي خدمة إرسال أخرى
- رسالة "Invalid API Key" أو "Authentication failed"

### الإصلاح:

**على خادم المحلل:**
```bash
# عرض المفتاح الحالي
cat .env | grep INGEST_API_KEY
```

**على خادم المستشعر:**
```bash
# التحقق من تطابق المفتاح
cat .env | grep INGEST_API_KEY

# تحديث المفتاح ليطابق المحلل
nano .env
# INGEST_API_KEY=<نفس_المفتاح_من_المحلل>

# إعادة تشغيل الحاويات
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

---

## 3) خطأ HTTP 500 مع asyncpg ProgrammingError (عدم تطابق مخطط قاعدة البيانات)

### الأعراض:
- خطأ `500 Internal Server Error` في API
- رسالة `asyncpg.exceptions.UndefinedTableError` أو `ProgrammingError` في السجلات
- فشل بعد تحديث الكود مع وجود volume قديم

### الإصلاح (الطريقة أ - إعادة تعيين كاملة، فقدان البيانات):
```bash
cd /path/to/analyzer

# إيقاف وحذف كل شيء بما في ذلك volumes
docker compose down -v

# إعادة البناء والتشغيل
docker compose up --build -d
```

### الإصلاح (الطريقة ب - الحفاظ على البيانات):
```bash
# تطبيق الترحيل يدوياً عبر psql إذا توفر ملف SQL
docker compose exec postgres psql -U <user> -d <database> -f /path/to/migration.sql
```

---

## 4) تحذيرات "orphan containers" عند تشغيل compose على نفس الجهاز

### الأعراض:
- رسالة: `Found orphan containers for this project`
- تعارض بين حاويات المحلل والمستشعر على نفس الخادم

### الإصلاح:

**الخيار 1: استخدام --remove-orphans**
```bash
docker compose up -d --remove-orphans
```

**الخيار 2: تحديد اسم مشروع مختلف لكل stack**
```bash
# للمحلل
COMPOSE_PROJECT_NAME=analyzer docker compose up -d

# للمستشعر
COMPOSE_PROJECT_NAME=sensor docker compose -f docker-compose.sensor.yml up -d
```

**أو عبر ملف .env:**
```bash
# في مجلد المحلل
echo "COMPOSE_PROJECT_NAME=analyzer" >> .env

# في مجلد المستشعر
echo "COMPOSE_PROJECT_NAME=sensor" >> .env
```

---

## 5) خطأ "No module named 'agents'" في حاويات المستشعر

### الأعراض:
- فشل حاوية المستشعر عند البدء
- رسالة: `ModuleNotFoundError: No module named 'agents'`

### الإصلاح:

**الخطوة 1: تعديل ملف الاستيراد**
```bash
# تحرير الملف
nano agents/common/__init__.py

# تغيير من:
# from agents.common.ip_utils import ...
# إلى:
# from .ip_utils import ...
```

**الخطوة 2: إعادة البناء بدون cache**
```bash
docker compose -f docker-compose.sensor.yml build --no-cache flow-collector suricata-shipper

# إعادة التشغيل
docker compose -f docker-compose.sensor.yml up -d
```

---

## 6) أخطاء تحليل قواعد Suricata (مثل modbus/ftp/dnp3)

### الأعراض:
- فشل Suricata في البدء
- رسائل خطأ مثل: `rule parsing error` أو `unknown protocol`
- ذكر SID معين في رسالة الخطأ

### الإصلاح (الطريقة أ - تعطيل القاعدة المشكلة):
```bash
# البحث عن القاعدة
docker exec -it suricata grep -rn "sid:XXXX" /var/lib/suricata/rules/

# تعليق القاعدة (إضافة # في البداية)
docker exec -it suricata sed -i 's/^\(.*sid:XXXX.*\)$/#\1/' /var/lib/suricata/rules/suricata.rules

# إعادة تشغيل Suricata
docker compose -f docker-compose.sensor.yml restart suricata
```

### الإصلاح (الطريقة ب - تفعيل البروتوكول في suricata.yaml):
```bash
# تحرير ملف الإعدادات
nano agents/suricata/suricata.yaml

# تفعيل البروتوكول المطلوب، مثال:
# ftp:
#   enabled: yes
# أو:
# modbus:
#   enabled: yes
#   detection-enabled: yes

# إعادة البناء والتشغيل
docker compose -f docker-compose.sensor.yml up --build -d suricata
```

---

## 7) ملف /var/log/auth.log غير موجود (Kali/بعض التوزيعات)

### الأعراض:
- `auth_collector` لا يرسل بيانات
- خطأ: `FileNotFoundError: /var/log/auth.log`
- لا توجد أحداث تسجيل دخول في لوحة التحكم

### الإصلاح:

**الخطوة 1: تحديد مسار السجل الصحيح**
```bash
# في Debian/Ubuntu
ls -la /var/log/auth.log

# في RHEL/CentOS/Fedora
ls -la /var/log/secure

# في Arch/بعض الأنظمة
journalctl -u sshd --no-pager | head
```

**الخطوة 2: تفعيل rsyslog إذا لزم الأمر**
```bash
# تثبيت وتفعيل rsyslog
sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

**الخطوة 3: تحديث mount في docker-compose.sensor.yml**
```yaml
volumes:
  - /var/log/secure:/var/log/auth.log:ro  # لأنظمة RHEL
```

**الخطوة 4: إعادة التشغيل**
```bash
docker compose -f docker-compose.sensor.yml up -d auth_collector
```

---

## 8) تغير عنوان IP بعد إعادة تشغيل الشبكة (DHCP)

### الأعراض:
- المستشعرات لا ترسل بيانات فجأة بعد إعادة التشغيل
- كان كل شيء يعمل سابقاً
- خطأ اتصال في سجلات المستشعر

### الإصلاح:

**على خادم المحلل:**
```bash
# معرفة العنوان الجديد
ip addr show | grep "inet "
# أو
hostname -I
```

**على خادم المستشعر:**
```bash
# تحديث العنوان في .env
nano .env
# ANALYZER_HOST=<العنوان_الجديد>

# إعادة التشغيل
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d
```

> **ملاحظة:** يُفضل استخدام IP ثابت لتجنب هذه المشكلة.

---

## 9) سلوك الإيقاف الآمن وإعادة التشغيل

### معلومات هامة:
- عند إيقاف الحاويات: البيانات في volumes تبقى محفوظة
- عند استخدام `down -v`: يتم حذف قاعدة البيانات والبيانات!
- الحاويات لا تبدأ تلقائياً بعد إعادة تشغيل الخادم (إلا إذا تم إعدادها)

### أوامر الإيقاف الآمن:
```bash
# إيقاف بدون حذف البيانات
docker compose stop

# أو إيقاف مع إزالة الحاويات (volumes تبقى)
docker compose down
```

### أوامر التشغيل بعد إعادة تشغيل الخادم:
```bash
# المحلل
cd /path/to/analyzer
docker compose up -d

# المستشعر
cd /path/to/sensor
docker compose -f docker-compose.sensor.yml up -d
```

### تفعيل التشغيل التلقائي:
```bash
# إضافة restart policy في docker-compose.yml لكل خدمة:
# restart: unless-stopped
```

---

## 10) إعادة تعيين كاملة (البدء من الصفر)

### المحلل (Analyzer):
```bash
cd /path/to/analyzer

# إيقاف وحذف كل شيء
docker compose down -v

# حذف الصور (اختياري)
docker compose down --rmi all

# تنظيف Docker
docker system prune -f
docker volume prune -f

# إعادة البناء والتشغيل
docker compose up --build -d

# التحقق
docker compose ps
docker compose logs --tail=50
curl http://localhost:8000/api/v1/health
```

### المستشعر (Sensor):
```bash
cd /path/to/sensor

# إيقاف
docker compose -f docker-compose.sensor.yml down

# حذف الصور (اختياري)
docker compose -f docker-compose.sensor.yml down --rmi all

# تنظيف
docker system prune -f

# إعادة البناء والتشغيل
docker compose -f docker-compose.sensor.yml up --build -d

# التحقق
docker compose -f docker-compose.sensor.yml ps
docker compose -f docker-compose.sensor.yml logs --tail=50
```

---

## 11) امتلاء مساحة القرص / Docker storage

### الأعراض:
- خطأ: `no space left on device`
- فشل عمليات البناء
- أخطاء كتابة في Postgres
- بطء شديد في الأداء

### الإصلاح السريع (تنظيف Docker):
```bash
# تنظيف الحاويات المتوقفة والشبكات غير المستخدمة
docker system prune -f

# تنظيف volumes غير المستخدمة (احترس من حذف البيانات!)
docker volume prune -f

# تنظيف cache البناء
docker builder prune -f

# تنظيف شامل (احترس!)
docker system prune -a --volumes -f
```

### فحص استخدام المساحة:
```bash
# استخدام Docker
docker system df

# استخدام القرص العام
df -h

# أكبر الملفات في /var/lib/docker
sudo du -sh /var/lib/docker/*
```

### توسيع المساحة (Cloud/VMware - الحل الآمن والمجرب):

> هذا الحل مناسب عندما تكون قد كبّرت القرص من VMware/Cloud Console ولكن النظام لا يرى المساحة الجديدة.

**الخطوة 0: فحص الوضع الحالي**
```bash
lsblk
df -h /
```

**الخطوة 1: تكبير البارتيشن sda3 ليأخذ كل المساحة**
```bash
sudo growpart /dev/sda 3
```
> هذا الأمر آمن: يكبّر البارتيشن بدون المساس بالبيانات.

**الخطوة 2: إعلام LVM بالمساحة الجديدة**
```bash
sudo pvresize /dev/sda3
```

**الخطوة 3: توسيع Logical Volume**
```bash
sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv
```

**الخطوة 4: توسيع نظام الملفات**
```bash
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv
```

**الخطوة 5: التأكد**
```bash
df -h /
```

---

### توسيع المساحة (LVM العام):
```bash
# فحص الأقراص
lsblk
df -h

# توسيع Physical Volume (إذا تمت إضافة مساحة للقرص)
sudo pvresize /dev/sdX

# توسيع Logical Volume
sudo lvextend -l +100%FREE /dev/mapper/vg_name-lv_name

# توسيع نظام الملفات
sudo resize2fs /dev/mapper/vg_name-lv_name  # لـ ext4
# أو
sudo xfs_growfs /mount/point  # لـ xfs
```

### نقل Docker إلى قرص جديد:
```bash
# إيقاف Docker
sudo systemctl stop docker

# نسخ البيانات
sudo rsync -aP /var/lib/docker/ /new/disk/docker/

# تحديث fstab
echo '/dev/sdY1 /var/lib/docker ext4 defaults 0 2' | sudo tee -a /etc/fstab

# أو إنشاء symbolic link
sudo mv /var/lib/docker /var/lib/docker.bak
sudo ln -s /new/disk/docker /var/lib/docker

# تشغيل Docker
sudo systemctl start docker

# التحقق
docker ps
```

---

## 12) قائمة التحقق السريع

### التحقق من المحلل (Analyzer):
```bash
# حالة الحاويات
docker compose ps

# السجلات (آخر 100 سطر)
docker compose logs --tail=100

# صحة API
curl http://localhost:8000/api/v1/health

# فتح لوحة التحكم في المتصفح
# http://<ANALYZER_IP>:3000
```

### التحقق من المستشعر (Sensor):
```bash
# حالة الحاويات
docker compose -f docker-compose.sensor.yml ps

# سجلات كل خدمة
docker compose -f docker-compose.sensor.yml logs flow-collector --tail=50
docker compose -f docker-compose.sensor.yml logs suricata-shipper --tail=50
docker compose -f docker-compose.sensor.yml logs auth_collector --tail=50

# التحقق من الاتصال بالمحلل
curl http://<ANALYZER_HOST>:8000/api/v1/health
```

### علامات النجاح:
- ✅ جميع الحاويات في حالة `Up` و `healthy`
- ✅ لا توجد أخطاء متكررة في السجلات
- ✅ `/api/v1/health` يُرجع `{"status": "healthy"}`
- ✅ الأحداث تظهر وتتزايد في لوحة التحكم

---

> **تذكير:** هذا الدليل للتشغيل السريع فقط. لا يتضمن إعدادات الأمان والتقوية.
