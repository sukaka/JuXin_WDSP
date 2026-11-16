BEGIN;

ALTER TABLE api_parameter_statistics
    DROP COLUMN IF EXISTS format_candidate,
    DROP COLUMN IF EXISTS format_candidate_ratio;

ALTER TABLE api_parameter_value_obs
    DROP COLUMN IF EXISTS format_sample_count,
    DROP COLUMN IF EXISTS format_counts;

COMMIT;
