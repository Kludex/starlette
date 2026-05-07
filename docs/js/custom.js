function shuffle(array) {
    var currentIndex = array.length, temporaryValue, randomIndex;
    while (0 !== currentIndex) {
        randomIndex = Math.floor(Math.random() * currentIndex);
        currentIndex -= 1;
        temporaryValue = array[currentIndex];
        array[currentIndex] = array[randomIndex];
        array[randomIndex] = temporaryValue;
    }
    return array;
}

async function showRandomAnnouncement(groupId, timeInterval) {
    const announceGroup = document.getElementById(groupId);
    if (announceGroup) {
        let children = [].slice.call(announceGroup.children);
        children = shuffle(children)
        let index = 0
        const announceRandom = () => {
            children.forEach((el, i) => { el.style.display = "none" });
            children[index].style.display = "block"
            index = (index + 1) % children.length
        }
        announceRandom()
        setInterval(announceRandom, timeInterval)
    }
}

async function main() {
    showRandomAnnouncement('announce-msg', 5000)
}

document$.subscribe(() => {
    main()
})
