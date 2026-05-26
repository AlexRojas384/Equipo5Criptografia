"""
merge_indexes.py — Fusiona todos los _index.md de subcarpetas en test_cases_INDEX.md
"""
import os
import re

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Subcarpetas en orden
SUBCARPETAS = [
    "01_autenticacion",
    "02_gestion_usuarios",
    "03_roles_y_permisos",
    "04_certificados_y_firma",
    "05_expedientes",
    "06_verificacion_expedientes",
    "07_auditoria",
    "08_seguridad_criptografica",
]

TITULOS = {
    "01_autenticacion":             "Autenticación",
    "02_gestion_usuarios":          "Gestión de Usuarios",
    "03_roles_y_permisos":          "Roles y Permisos",
    "04_certificados_y_firma":      "Certificados y Firma Digital",
    "05_expedientes":               "Expedientes (CRUD)",
    "06_verificacion_expedientes":  "Verificación de Expedientes",
    "07_auditoria":                 "Auditoría",
    "08_seguridad_criptografica":   "Seguridad Criptográfica",
}


def extraer_filas_tabla(contenido: str) -> list[str]:
    """Extrae las filas de datos de una tabla markdown (ignora encabezado y separador)."""
    lineas = contenido.strip().splitlines()
    filas = []
    tabla_iniciada = False
    separador_visto = False
    for linea in lineas:
        linea_strip = linea.strip()
        if not linea_strip.startswith("|"):
            if tabla_iniciada:
                break  # fin de la tabla
            continue
        # Detectar si es separador (|---|---|...)
        if re.match(r"^\|[\s\-:]+\|", linea_strip):
            separador_visto = True
            tabla_iniciada = True
            continue
        if not tabla_iniciada:
            tabla_iniciada = True
            continue  # skip header row
        if separador_visto:
            filas.append(linea_strip)
    return filas


def main():
    output_lines = []

    # Encabezado
    output_lines.append("# Índice Maestro de Casos de Prueba — Casa Monarca")
    output_lines.append("")
    output_lines.append("> Documento generado automáticamente por `merge_indexes.py`.")
    output_lines.append("> Contiene todos los casos de prueba del sistema organizados por categoría.")
    output_lines.append(">")
    output_lines.append("> **Sistema:** Plataforma de gestión segura de expedientes para Casa Monarca")
    output_lines.append("> **Arquitectura de Seguridad:** Doble Llave (Login Key + Firma SAT)")
    output_lines.append("> **Roles:** Administrador, Coordinador (5 tipos), Operativo, Usuario")
    output_lines.append("")
    output_lines.append("---")
    output_lines.append("")

    total_casos = 0

    for carpeta in SUBCARPETAS:
        index_path = os.path.join(SCRIPT_DIR, carpeta, "_index.md")
        if not os.path.exists(index_path):
            print(f"  [WARN] No se encontro: {index_path}")
            continue

        with open(index_path, "r", encoding="utf-8") as f:
            contenido = f.read()

        filas = extraer_filas_tabla(contenido)
        n = len(filas)
        total_casos += n

        titulo = TITULOS.get(carpeta, carpeta)
        output_lines.append(f"## {titulo}")
        output_lines.append("")
        output_lines.append(f"📁 `{carpeta}/` — **{n} casos**")
        output_lines.append("")
        output_lines.append("| Roles | Descripción | Metodología | ID caso |")
        output_lines.append("|---|---|---|---|")
        for fila in filas:
            output_lines.append(fila)
        output_lines.append("")
        output_lines.append("---")
        output_lines.append("")

        print(f"  [OK] {carpeta}: {n} casos")

    # Resumen al final
    output_lines.append(f"## Resumen")
    output_lines.append("")
    output_lines.append(f"**Total de casos de prueba: {total_casos}**")
    output_lines.append("")
    output_lines.append("| Categoría | Casos |")
    output_lines.append("|---|---|")
    for carpeta in SUBCARPETAS:
        index_path = os.path.join(SCRIPT_DIR, carpeta, "_index.md")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                n = len(extraer_filas_tabla(f.read()))
            output_lines.append(f"| {TITULOS.get(carpeta, carpeta)} | {n} |")
    output_lines.append(f"| **Total** | **{total_casos}** |")
    output_lines.append("")

    # Escribir archivo
    out_path = os.path.join(SCRIPT_DIR, "test_cases_INDEX.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(output_lines))

    print(f"\nGenerado: {out_path}")
    print(f"Total de casos: {total_casos}")


if __name__ == "__main__":
    main()
