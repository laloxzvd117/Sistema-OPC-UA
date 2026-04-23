
## ProyectoInterfaz — Sistema de Monitoreo de Línea de Producción Industrial

Sistema académico de monitoreo en tiempo real para una línea de producción de botellas, desarrollado como proyecto de redes y sistemas distribuidos. Basado en Sistema OPC-UA.

### Descripción

La aplicación integra sensores físicos ESP32 con un stack de software completo que permite supervisar, controlar y registrar el estado de una línea de producción simulada. Los datos de los sensores se transmiten vía HTTP/REST en formato JSON hacia un servidor backend, donde son procesados y almacenados para su visualización en dashboards web diferenciados por rol.

### Tecnologías

- **Hardware:** ESP32 (sensores físicos con comunicación HTTP/REST)
- **Backend:** Python + Flask, servidor de adquisición OPC UA
- **Base de datos:** PostgreSQL
- **Frontend:** HTML/CSS con dashboards para Administrador y Empleado
- **Infraestructura:** VirtualBox sobre Linux, pfSense como firewall/router
- **Red:** Subred `192.168.10.0/24` con IPs fijas por servicio

### Características principales

- Autenticación con roles (`Administrador` / `Empleado`) y sesiones seguras con tokens
- Protección contra inyección SQL y sanitización de entradas
- Control y monitoreo de línea de producción en tiempo real 
- Gestión de usuarios con CRUD completo
- Arquitectura distribuida en máquinas virtuales con firewall dedicado
