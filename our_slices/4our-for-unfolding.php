<?php
    $a = 0;
    // implicit leak $x -> f
    for ($x = 0; $x <= 10; $x++) {
        f();
    }
    // explicit leak $x -> $b -> f
    for ($b = $x; $b <= 10; $b++){
        f($b);
    }
?>