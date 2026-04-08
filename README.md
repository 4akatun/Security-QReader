# Secure QR Reader - Lector de Códigos QR Seguro

Aplicación Android de lector de códigos QR con **todas las medidas de seguridad implementadas**.

## 📋 Medidas de Seguridad Implementadas

### 1. Ofuscación de Código (R8/ProGuard)
- Ofuscación completa de nombres de clases y métodos
- Eliminación de código no utilizado
- Eliminación de logs en builds de producción
- Configurado en `proguard-rules.pro`

### 2. Validación Segura de URLs
- Detección de patrones peligrosos (XSS, JavaScript, data URIs)
- Prevención de inyección de credenciales en URLs
- Detección de homoglyphs (caracteres similares para phishing)
- Validación de dominios y detección de acortadores
- Limpieza de parámetros de tracking

### 3. Network Security Configuration
- HTTPS obligatorio (cleartext traffic deshabilitado)
- Certificate pinning configurable
- Configuración separada para debug/release

### 4. Permisos Mínimos Necesarios
- Solo permiso de cámara (requerido para escanear)
- Solo permiso de internet (para abrir URLs)
- Sin permisos innecesarios

### 5. Prevención de Screenshots
- `FLAG_SECURE` habilitado en todas las actividades
- Previene capturas de pantalla y grabación

### 6. Validación de Contenido QR
- Clasificación segura por tipo de contenido
- Validación de URLs, emails, teléfonos, SMS, WiFi, contactos
- Advertencias de seguridad por tipo de contenido

### 7. Secure SharedPreferences (Encriptación)
- Uso de Android Keystore (hardware-backed)
- Encriptación AES-256-GCM para valores
- Encriptación AES-256-SIV para claves
- Verificación de integridad del keystore

### 8. App Integrity API / Verificación de Firma
- Verificación de firma de la aplicación
- Detección de apps empaquetadas/modificadas
- Verificación de instalador confiable
- Detección de emuladores

### 9. Security Provider (Conscrypt)
- Proveedor de seguridad actualizado
- Independiente del proveedor del sistema
- Parches de seguridad más recientes

### 10. Backup y Data Extraction Deshabilitados
- `android:allowBackup="false"`
- `backup_rules.xml` excluye todos los datos
- `data_extraction_rules.xml` previene extracción

### 11. No Guardar Datos Sensibles en Logs
- Logs eliminados en producción vía ProGuard
- Mensajes genéricos en caso de error

### 12. Input Validation
- Validación de longitud máxima
- Sanitización de todo el contenido escaneado
- Validación de esquemas URL

## 📁 Estructura del Proyecto

```
app/
├── src/main/
│   ├── java/com/secure/qrreader/
│   │   ├── MainActivity.kt              # Actividad principal
│   │   ├── SecureApplication.kt         # Application con hardening
│   │   └── security/
│   │       ├── UrlValidator.kt          # Validación de URLs
│   │       ├── QrContentValidator.kt    # Validación de contenido QR
│   │       ├── SecureStorage.kt         # Almacenamiento encriptado
│   │       └── SecurityUtils.kt         # Utilidades de seguridad
│   │
│   ├── res/
│   │   ├── layout/activity_main.xml
│   │   ├── values/
│   │   ├── values-es/                   # Traducción al español
│   │   ├── xml/
│   │   │   ├── network_security_config.xml
│   │   │   ├── backup_rules.xml
│   │   │   └── data_extraction_rules.xml
│   │   └── drawable/
│   │
│   └── AndroidManifest.xml
│
├── proguard-rules.pro                   # Reglas de ofuscación
└── build.gradle.kts                     # Configuración de build

```

## 🔧 Configuración de Build

### Build de Release (Producción)
```bash
./gradlew assembleRelease
```

El APK se genera en: `app/build/outputs/apk/release/app-release.apk`

### Build de Debug
```bash
./gradlew assembleDebug
```

## ⚙️ Configuración para Producción

### 1. Configurar Firma de Producción

Obtén el hash de tu firma de producción:

```kotlin
// Ejecuta esto en tu app de producción
val hash = SecurityUtils.getAppSignatureHash(context)
println("Signature hash: $hash")
```

Luego actualiza `SecureApplication.kt`:

```kotlin
private fun getExpectedSignatureHash(): String? {
    return "TU_HASH_DE_PRODUCCION_AQUI"
}
```

### 2. Configurar Keystore para Firmar

Crea `keystore.properties` en la raíz del proyecto:

```properties
storePassword=tu_password
keyPassword=tu_key_password
keyAlias=tu_alias
storeFile=/ruta/a/tu/keystore.jks
```

Actualiza `app/build.gradle.kts`:

```kotlin
android {
    signingConfigs {
        create("release") {
            storeFile = file(System.getenv["KEYSTORE_FILE"] ?: "keystore.jks")
            storePassword = System.getenv["KEYSTORE_PASSWORD"]
            keyAlias = System.getenv["KEY_ALIAS"]
            keyPassword = System.getenv["KEY_PASSWORD"]
        }
    }
    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}
```

### 3. Certificate Pinning (Opcional)

Para habilitar certificate pinning, actualiza `network_security_config.xml`:

```xml
<domain includeSubdomains="true">api.tudominio.com</domain>
<pin-set expiration="2026-03-31">
    <pin digest="SHA-256">HASH_DEL_CERTIFICADO</pin>
</domain>
```

## 🛡️ Características de Seguridad Adicionales

### Verificación en Tiempo de Ejecución
- La app verifica su integridad al iniciarse
- Verificación al reanudar desde segundo plano
- Detección de entorno sospechoso (emulador, depuración)

### ML Kit Offline
- El escaneo se realiza completamente offline
- No se envían datos a servidores externos
- Google ML Kit es una biblioteca verificada y segura

### CameraX Seguro
- Uso de CameraX en lugar de Camera API legacy
- Mejor control de permisos y ciclo de vida
- Sin almacenamiento de imágenes capturadas

## 📱 Requisitos del Sistema

- **Android mínimo:** API 26 (Android 8.0)
- **Android target:** API 34 (Android 14)
- **Cámara:** Requerida para escanear QR

## 🚀 Uso

1. **Conceder permiso de cámara** cuando se solicite
2. **Apuntar al código QR** dentro del marco
3. **Revisar la evaluación de seguridad** antes de abrir URLs
4. **Elegir acción:** Abrir URL, Copiar contenido, o Cancelar

## 📝 Notas de Seguridad

### Para el Usuario
- ✅ Esta app **NO** guarda historial de escaneos
- ✅ Esta app **NO** envía datos a internet (excepto al abrir URLs)
- ✅ Esta app **NO** toma fotos ni graba video
- ✅ Todo el procesamiento es local en tu dispositivo

### Para el Desarrollador
- ⚠️ Reemplaza el hash de firma antes de publicar
- ⚠️ Firma tu APK con un keystore seguro
- ⚠️ Considera habilitar Play App Integrity en producción
- ⚠️ Revisa y actualiza las reglas de ProGuard según necesites

## 📄 Licencia

Este proyecto es de código abierto y puede ser modificado libremente.

## 🔗 Dependencias Principales

- **CameraX:** `androidx.camera:camera-*`
- **ML Kit Barcode:** `com.google.mlkit:barcode-scanning`
- **EncryptedSharedPreferences:** `androidx.security:security-crypto-ktx`
- **Conscrypt:** `org.conscrypt:conscrypt-android`
- **Material Design:** `com.google.android.material:material`
