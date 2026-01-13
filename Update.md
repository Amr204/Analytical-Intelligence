# 🔄 دليل التحديث - Analytical-Intelligence

> تحديث المشروع عند سحب نسخة جديدة من GitHub

---

## 📥 سحب التحديثات من GitHub

```bash
cd Analytical-Intelligence

# حفظ التغييرات المحلية (إن وجدت)
git stash

# سحب آخر التحديثات
git pull origin main

# استعادة التغييرات المحلية
git stash pop
```

---

## 🖥️ Analysis Server Update

### الحالة 1: تغييرات في الكود فقط

```bash
# إعادة تشغيل مع البناء
docker compose -f docker-compose.analysis.yml up -d --build
```

### الحالة 2: تغييرات في Dockerfile أو requirements.txt

```bash
# بناء من الصفر (بدون cache)
docker compose -f docker-compose.analysis.yml build --no-cache
docker compose -f docker-compose.analysis.yml up -d
```

### الحالة 3: تغييرات في docker-compose.yml

```bash
# إيقاف ثم تشغيل
docker compose -f docker-compose.analysis.yml down
docker compose -f docker-compose.analysis.yml up -d --build
```

### الحالة 4: تغييرات في قاعدة البيانات (Schema)

**الخيار أ: إعادة تعيين كاملة** ⚠️ (فقدان البيانات)
```bash
docker compose -f docker-compose.analysis.yml down -v
docker compose -f docker-compose.analysis.yml up -d --build
```

**الخيار ب: تطبيق SQL يدوياً** (الحفاظ على البيانات)
```bash
# افتح psql
docker exec -it ai_db-postgres psql -U ai -d ai_db

# نفّذ أوامر SQL المطلوبة من الـ changelog
# مثال:
# ALTER TABLE detections ADD COLUMN new_field TEXT;

# اخرج
\q
```

### الحالة 5: تغييرات في .env.example

```bash
# قارن الملفين
diff .env .env.example

# أضف المتغيرات الجديدة يدوياً
nano .env
```

---

## 🔍 Sensor Server Update

### الحالة 1: تغييرات في الكود فقط

```bash
docker compose -f docker-compose.sensor.yml up -d --build
```

### الحالة 2: تغييرات في Dockerfile أو requirements.txt

```bash
docker compose -f docker-compose.sensor.yml build --no-cache
docker compose -f docker-compose.sensor.yml up -d
```

### الحالة 3: تغييرات في docker-compose.yml

```bash
docker compose -f docker-compose.sensor.yml down
docker compose -f docker-compose.sensor.yml up -d --build
```

### الحالة 4: تغييرات في .env.example

```bash
diff .env .env.example
nano .env
```

---

## ✅ Verify

### Analysis Server

```bash
# حالة الحاويات
docker compose -f docker-compose.analysis.yml ps

# السجلات (آخر 50 سطر)
docker compose -f docker-compose.analysis.yml logs --tail=50

# فحص الـ Health
curl -s http://localhost:8000/api/v1/health | jq

# المتوقع:
# {"status":"ok","timestamp":"...","version":"1.0.0"}
```

### Sensor Server

```bash
# حالة الحاويات
docker compose -f docker-compose.sensor.yml ps

# السجلات
docker compose -f docker-compose.sensor.yml logs --tail=50

# تحقق من الاتصال بـ Analysis
curl -s http://<ANALYZER_IP>:8000/api/v1/health
```

---

## ⏪ Rollback

### العودة لـ commit سابق

```bash
# عرض آخر 5 commits
git log --oneline -5

# العودة لـ commit معين
git checkout <COMMIT_HASH>

# إعادة بناء وتشغيل
docker compose -f docker-compose.analysis.yml up -d --build
# أو
docker compose -f docker-compose.sensor.yml up -d --build
```

### العودة للنسخة الأخيرة المستقرة

```bash
git checkout main
docker compose -f docker-compose.analysis.yml up -d --build
```

### استعادة قاعدة البيانات من نسخة احتياطية

```bash
# إذا كنت قد أخذت نسخة احتياطية قبل التحديث:
docker exec -i ai_db-postgres psql -U ai -d ai_db < backup.sql
```

---

## 💡 نصائح سريعة

| الحالة | الأمر |
|--------|-------|
| إعادة تشغيل حاوية واحدة | `docker compose restart backend` |
| مسح الـ images القديمة | `docker image prune -a` |
| مسح كل شيء | `docker system prune -a` ⚠️ |
| نسخة احتياطية للـ DB | `docker exec ai_db-postgres pg_dump -U ai ai_db > backup.sql` |

---

## 📋 قائمة مراجعة التحديث

- [ ] سحبت التحديثات: `git pull`
- [ ] راجعت الـ changelog للتغييرات المهمة
- [ ] قارنت `.env.example` مع `.env`
- [ ] أعدت بناء الحاويات
- [ ] فحصت الـ Health endpoint
- [ ] راجعت السجلات للأخطاء
