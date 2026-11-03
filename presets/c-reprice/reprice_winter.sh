#!/bin/bash
# Winter repricing: +10% on active winter and snow prices.
psql shop -c "UPDATE prices SET amount = round(amount * 1.10, 2) WHERE category = 'winter' OR category = 'snow' AND active"
