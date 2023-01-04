<?php
    $a = 0;
    // implicit leak $x -> g
    for ($x = 0; $x <= 10; $x++) {
        g();
    }
    // explicit leak $x -> $b -> f
    for ($b = $x; $b <= 10; $b++){
        f($b);
    }
?>