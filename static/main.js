function updateFlavours() {
    // we get drink_options const from html
    const brandSelect = document.getElementById("brand");
    const flavourSelect = document.getElementById("flavour");
    const selectedBrand = brandSelect.value;

    flavourSelect.innerHTML = '<option value="">Select Flavour</option>';

    if(selectedBrand && drinkOptions[selectedBrand]) {
        drinkOptions[selectedBrand].forEach(flavour => {
            const opt = document.createElement("option");
            opt.value = flavour;
            opt.innerText = flavour;
            flavourSelect.appendChild(opt);
        });
    }
}
