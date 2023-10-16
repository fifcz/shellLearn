#!/bin/bash
# can not start this shell
# temp table can not execute
# Connect to PostgreSQL database and create temporary table, export data, and drop table in one session
/home/kingbase/cluster/kingbasecluster/db/bin/ksql -U fsphn_data -W "Fd_pwd.#3459" -p 54321 fsphn << EOF
CREATE TEMPORARY TABLE temp_export AS (
    SELECT
        a.credit_code,
        c.name AS region,
        EXTRACT(YEAR FROM a.created_date) AS year,
        EXTRACT(MONTH FROM a.created_date) AS month,
        a.status
    FROM
        hn_common_ent_auth_info a
        INNER JOIN hn_common_register_info b ON a.credit_code = b.credit_code
        LEFT JOIN common_dict_district c ON b.off_area_code = c.code
    WHERE
        a.created_date > '2023-04-01'
    UNION
    SELECT
        a.credit_code,
        c.name AS region,
        EXTRACT(YEAR FROM a.created_date) AS year,
        EXTRACT(MONTH FROM a.created_date) AS month,
        a.status
    FROM
        (
            SELECT *
            FROM hn_common_ent_auth_info
            WHERE credit_code NOT IN (
                SELECT credit_code
                FROM hn_common_register_info
                WHERE account_type = '01'
            )
        ) a
        INNER JOIN hn_common_exist_customer_info b ON a.credit_code = b.credit_code
        LEFT JOIN common_dict_district c ON b.off_area_code = c.code
    WHERE
        a.created_date > '2023-04-01'
);

SELECT DISTINCT year, month, region
FROM temp_export
ORDER BY year, month, region;

-- Iterate through the result using while loop
DO \$\$
DECLARE
    export_record RECORD;
BEGIN
    FOR export_record IN SELECT DISTINCT year, month, region FROM temp_export ORDER BY year, month, region LOOP
        -- Create the directory if it doesn't exist
        EXECUTE FORMAT('mkdir -p "/data/export/%s/%s/%s"', export_record.year, export_record.month, export_record.region);

        -- Export data for the specific year, month, and region combination
        EXECUTE FORMAT(
            'COPY (
                SELECT *
                FROM temp_export
                WHERE year = %L AND month = %L AND region = %L
            ) TO ''/data/export/%s/%s/%s/export.txt'';',
            export_record.year, export_record.month, export_record.region,
            export_record.year, export_record.month, export_record.region
        );
    END LOOP;
END;
\$\$ LANGUAGE plpgsql;

DROP TABLE temp_export;
EOF
