# Stats Dashboard Module

Panel de estadísticas en tiempo real para el servidor HTTP zhttpd.

## 🚀 Características

- **Autenticación HTTP Basic Auth**: Acceso seguro con credenciales
- **Estadísticas en Tiempo Real**: Actualización automática cada 2 segundos
- **Múltiples Métricas**:
  - Clientes activos concurrentes
  - Total de requests procesados
  - Tiempo promedio de respuesta
  - Tráfico de red (bytes/MB enviados)
  - Requests por segundo
- **Visualizaciones Interactivas**: 4 gráficas con Chart.js
- **Historial**: Datos de los últimos 60 segundos
- **Diseño Premium**: Tema oscuro moderno y responsivo

## 🔐 Credenciales de Acceso

Por defecto, las credenciales son:
- **Usuario**: `admin`
- **Contraseña**: `stats123`

## 📡 API Endpoints

El módulo expone los siguientes endpoints (requieren autenticación):

### GET `/api/stats/current`
Retorna las estadísticas actuales del servidor.

**Respuesta**:
```json
{
  "uptime_sec": 3600,
  "active_clients": 5,
  "total_requests": 15234,
  "total_bytes_sent": 52428800,
  "total_mb_sent": 50.00,
  "avg_response_ms": 12,
  "requests_per_sec": 4.23,
  "timestamp": 1703088000
}
```

### GET `/api/stats/history`
Retorna los datos históricos (últimas 30 muestras).

**Respuesta**:
```json
{
  "history": [
    {
      "timestamp": 1703088000,
      "clients": 5,
      "rps": 8,
      "avg_ms": 10,
      "bytes_kb": 256
    },
    ...
  ]
}
```

### POST `/api/stats/reset`
Reinicia todos los contadores de estadísticas (requiere autenticación).

**Respuesta**:
```json
{
  "status": "reset_complete"
}
```

## 🌐 Acceso al Dashboard

1. Inicia el servidor zhttpd
2. Navega a: `http://localhost:8080/stats/login.html`
3. Ingresa las credenciales
4. Serás redirigido al dashboard

## 🔧 Arquitectura Técnica

### Backend (C Module)
- **Archivo**: `modules/mod_stats.c`
- **Rastreo thread-safe**: Contadores atómicos para concurrencia
- **Buffer circular**: Historial de 60 muestras
- **Autenticación**: HTTP Basic Auth integrada

### Frontend
- **HTML/CSS**: Diseño moderno con animaciones CSS
- **JavaScript**: Vanilla JS con fetch API
- **Chart.js**: Librería de visualización v4.4.0
- **Session Storage**: Gestión de sesión del lado del cliente

## 📝 Personalización

### Cambiar Credenciales

Edita `modules/mod_stats.c` línea 13:
```c
#define AUTH_HEADER "Authorization: Basic <tu_base64>"
```

Genera el nuevo Base64:
```bash
echo -n "usuario:contraseña" | base64
```

### Ajustar Intervalo de Actualización

Edita `site/stats/js/dashboard.js` línea 27:
```javascript
updateInterval = setInterval(fetchAndUpdate, 2000); // 2000ms = 2s
```

### Cambiar Tamaño del Historial

Edita `modules/mod_stats.c` línea 11:
```c
#define HISTORY_SIZE 60  // Número de muestras a guardar
```

## 🐛 Troubleshooting

**El módulo no carga**:
- Verifica que `modules.conf` incluye `load modules/mod_stats.dll`
- Asegúrate de compilar con `build.bat`

**Error 401 en el dashboard**:
- Verifica las credenciales en el código
- Limpia sessionStorage del navegador

**Las gráficas no se actualizan**:
- Verifica la consola del navegador para errores
- Asegúrate de que el servidor está corriendo
- Comprueba que Chart.js se carga correctamente

## 📄 Licencia

Este módulo es parte del proyecto zhttpd.
